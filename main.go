package main

import (
    "bytes"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "github.com/gin-gonic/gin"
    "github.com/robfig/cron/v3"
    "image"
    "image/jpeg"
    _ "image/png"
    _ "image/gif"
    "io/ioutil"
    "log"
    "mime/multipart"
    "net/http"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"
)

// ============================================================================
// TYPES & SORTING
// ============================================================================
type ImageFile struct {
    Path    string
    ModTime time.Time
}

type ByModTime []ImageFile

func (a ByModTime) Len() int           { return len(a) }
func (a ByModTime) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByModTime) Less(i, j int) bool { return a[i].ModTime.After(a[j].ModTime) }

// ============================================================================
// ALLOWED EXTENSIONS & MAGIC NUMBERS
// ============================================================================
var (
    allowedExtensions = map[string]bool{
        ".jpg":  true,
        ".jpeg": true,
        ".png":  true,
        ".gif":  true,
        ".webp": true,
        ".heic": true,
        ".heif": true,
    }

    magicNumbers = map[string][]byte{
        "jpeg": {0xFF, 0xD8, 0xFF},
        "png":  {0x89, 0x50, 0x4E, 0x47},
        "gif":  {0x47, 0x49, 0x46, 0x38},
        "webp": {0x52, 0x49, 0x46, 0x46},
    }
)

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
func isAllowedExtension(filename string) bool {
    ext := strings.ToLower(filepath.Ext(filename))
    return allowedExtensions[ext]
}

func isImageFile(file *multipart.FileHeader) (bool, error) {
    src, err := file.Open()
    if err != nil {
        return false, err
    }
    defer src.Close()

    buff := make([]byte, 8)
    _, err = src.Read(buff)
    if err != nil {
        return false, err
    }

    for _, magic := range magicNumbers {
        if bytes.HasPrefix(buff, magic) {
            return true, nil
        }
    }
    return false, nil
}

func validateImageUpload(file *multipart.FileHeader) error {
    if file.Size > 32*1024*1024 {
        return fmt.Errorf("file too large, maximum size is 32MB")
    }

    if !isAllowedExtension(file.Filename) {
        return fmt.Errorf("invalid file type, only images are allowed (jpg, jpeg, png, gif, webp, heic, heif)")
    }

    isImage, err := isImageFile(file)
    if err != nil {
        return fmt.Errorf("error validating file: %v", err)
    }
    if !isImage {
        return fmt.Errorf("invalid file content, file must be an actual image")
    }
    return nil
}

func generateAnonymousFilename(originalFilename string) string {
    ext := strings.ToLower(filepath.Ext(originalFilename))
    randomBytes := make([]byte, 16)
    rand.Read(randomBytes)

    hasher := sha256.New()
    hasher.Write(randomBytes)
    hasher.Write([]byte(time.Now().String()))
    hash := hex.EncodeToString(hasher.Sum(nil))

    return hash[:12] + ext
}

func removeMetadata(filepath string) error {
    data, err := ioutil.ReadFile(filepath)
    if err != nil {
        return err
    }

    reader := bytes.NewReader(data)
    img, format, err := image.Decode(reader)
    if err != nil {
        return fmt.Errorf("error decoding image: %v", err)
    }

    tempFile := filepath + ".tmp"
    out, err := os.Create(tempFile)
    if err != nil {
        return err
    }
    defer out.Close()

    switch format {
    case "jpeg":
        err = jpeg.Encode(out, img, &jpeg.Options{Quality: 95})
    default:
        _, err = out.Write(data)
    }

    if err != nil {
        os.Remove(tempFile)
        return fmt.Errorf("error encoding image: %v", err)
    }

    out.Close()

    if err := os.Rename(tempFile, filepath); err != nil {
        os.Remove(tempFile)
        return err
    }

    return nil
}

// ============================================================================
// FILE SERVER & CLEANUP
// ============================================================================
func customFileServer(urlPrefix string, dir string) gin.HandlerFunc {
    fs := http.FileServer(http.Dir(dir))
    fileServer := http.StripPrefix(urlPrefix, fs)

    return func(c *gin.Context) {
        c.Header("Cache-Control", "no-cache")
        c.Header("X-Content-Type-Options", "nosniff")

        ext := strings.ToLower(filepath.Ext(c.Request.URL.Path))
        switch ext {
        case ".jpg", ".jpeg":
            c.Header("Content-Type", "image/jpeg")
        case ".png":
            c.Header("Content-Type", "image/png")
        case ".gif":
            c.Header("Content-Type", "image/gif")
        case ".webp":
            c.Header("Content-Type", "image/webp")
        }

        fileServer.ServeHTTP(c.Writer, c.Request)
    }
}

func SecureDelete(path string) error {
    fileInfo, err := os.Stat(path)
    if err != nil {
        return err
    }

    file, err := os.OpenFile(path, os.O_WRONLY, 0666)
    if err != nil {
        return err
    }
    defer file.Close()

    for i := 0; i < 3; i++ {
        file.Seek(0, 0)
        randomData := make([]byte, 4096)
        remaining := fileInfo.Size()

        for remaining > 0 {
            writeSize := remaining
            if writeSize > 4096 {
                writeSize = 4096
            }

            _, err := rand.Read(randomData[:writeSize])
            if err != nil {
                return err
            }

            _, err = file.Write(randomData[:writeSize])
            if err != nil {
                return err
            }
            remaining -= writeSize
        }
        file.Sync()
    }

    return os.Remove(path)
}

func CleanupUploads() {
    loc, _ := time.LoadLocation("Local")
    currentTime := time.Now().In(loc)
    log.Printf("Starting daily cleanup at %v (Local Time: %s)",
        currentTime.Format("2006-01-02 15:04:05 MST"),
        loc.String())

    files, err := ioutil.ReadDir("uploads")
    if err != nil {
        log.Printf("Error reading uploads directory: %v", err)
        return
    }

    totalFiles := 0
    deletedFiles := 0
    errors := 0

    for _, file := range files {
        totalFiles++
        filePath := filepath.Join("uploads", file.Name())
        if file.IsDir() {
            continue
        }

        err := SecureDelete(filePath)
        if err != nil {
            log.Printf("Error deleting file %s: %v", filePath, err)
            errors++
        } else {
            deletedFiles++
        }
    }

    log.Printf("Cleanup completed: Processed %d files, Successfully deleted %d files, Errors: %d",
        totalFiles, deletedFiles, errors)
}

// ============================================================================
// MAIN
// ============================================================================
func main() {
    // Configure logging to include timestamp (but not IP)
    log.SetFlags(log.Ldate | log.Ltime)
    log.Println("Starting application...")

    cwd, err := os.Getwd()
    if err != nil {
        log.Fatalf("Failed to get working directory: %v", err)
    }

    uploadDir := filepath.Join(cwd, "uploads")
    if err := os.MkdirAll(uploadDir, 0755); err != nil {
        log.Fatalf("Failed to create uploads directory: %v", err)
    }

    staticDir := filepath.Join(cwd, "static")
    if err := os.MkdirAll(staticDir, 0755); err != nil {
        log.Fatalf("Failed to create static directory: %v", err)
    }

    // ----------------------------------------------------------------------------
    // REPLACE gin.Default() WITH A CUSTOM SETUP THAT OMITS IP ADDRESSES
    // ----------------------------------------------------------------------------
    r := gin.New()
    // Keep panic-recovery
    r.Use(gin.Recovery())

    // Custom no-IP logger middleware
    r.Use(func(c *gin.Context) {
        start := time.Now()
        method := c.Request.Method
        path := c.Request.URL.Path

        // Process request
        c.Next()

        status := c.Writer.Status()
        latency := time.Since(start)

        // No IP address is logged here
        log.Printf("[GIN] %v | %3d | %13v | %s  %s",
            start.Format("2006/01/02 - 15:04:05"),
            status,
            latency,
            method,
            path,
        )
    })
    // ----------------------------------------------------------------------------

    // Initialize cron scheduler with local time zone
    loc, err := time.LoadLocation("Local")
    if err != nil {
        log.Printf("Error loading local timezone: %v", err)
        loc = time.UTC
    }
    cronScheduler := cron.New(cron.WithLocation(loc))

    now := time.Now().In(loc)
    nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, loc)

    _, err = cronScheduler.AddFunc("0 0 * * *", func() {
        log.Printf("Cron job triggered at: %v (Local Time)", time.Now().In(loc))
        CleanupUploads()
    })
    if err != nil {
        log.Printf("Error setting up cron job: %v", err)
    } else {
        log.Printf("Cron job successfully scheduled for local midnight")
        log.Printf("Current local time: %v", now.Format("2006-01-02 15:04:05 MST"))
        log.Printf("Next cleanup scheduled for: %v", nextMidnight.Format("2006-01-02 15:04:05 MST"))
        log.Printf("Time until next cleanup: %v", time.Until(nextMidnight))
    }
    cronScheduler.Start()
    defer cronScheduler.Stop()

    // Set max multipart memory
    r.MaxMultipartMemory = 32 << 20 // 32 MB

    // Serve static assets & images
    r.Static("/static", staticDir)
    r.GET("/uploads/*filepath", customFileServer("/uploads", uploadDir))

    // Debug endpoint
    r.GET("/debug/image/*filepath", func(c *gin.Context) {
        path := c.Param("filepath")
        fullPath := filepath.Join(uploadDir, path[1:])

        data, err := ioutil.ReadFile(fullPath)
        if err != nil {
            c.String(http.StatusInternalServerError, "Error reading file: %v", err)
            return
        }
        if len(data) > 2 && data[0] == 0xFF && data[1] == 0xD8 {
            c.Header("Content-Type", "image/jpeg")
            c.Data(http.StatusOK, "image/jpeg", data)
        } else {
            c.String(http.StatusBadRequest, "Invalid JPEG file")
        }
    })

    // Manually check next cleanup
    r.GET("/next-cleanup", func(c *gin.Context) {
        entries := cronScheduler.Entries()
        if len(entries) > 0 {
            nextRun := entries[0].Next
            now := time.Now().In(loc)
            timeUntil := time.Until(nextRun)

            c.JSON(http.StatusOK, gin.H{
                "current_time": now.Format("2006-01-02 15:04:05 MST"),
                "next_cleanup": nextRun.Format("2006-01-02 15:04:05 MST"),
                "time_until":   timeUntil.String(),
                "timezone":     loc.String(),
            })
        } else {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "No scheduled cleanup found"})
        }
    })

    // Upload handler
    r.POST("/upload", func(c *gin.Context) {
        file, err := c.FormFile("file")
        if err != nil {
            log.Printf("Upload failed: %v", err)
            c.String(http.StatusBadRequest, "File upload failed: "+err.Error())
            return
        }

        log.Printf("Received file: %s (Size: %d bytes)", file.Filename, file.Size)

        if file.Size < 1024 {
            log.Printf("File too small: %d bytes", file.Size)
            c.String(http.StatusBadRequest, "File too small to be a valid image")
            return
        }

        if err := validateImageUpload(file); err != nil {
            log.Printf("Validation failed for %s: %v", file.Filename, err)
            c.String(http.StatusBadRequest, "Invalid file: "+err.Error())
            return
        }

        anonFilename := generateAnonymousFilename(file.Filename)
        filePath := filepath.Join(uploadDir, anonFilename)
        log.Printf("File will be saved as: %s", anonFilename)

        err = c.SaveUploadedFile(file, filePath)
        if err != nil {
            log.Printf("Failed to save file %s: %v", anonFilename, err)
            c.String(http.StatusBadRequest, "File save failed: "+err.Error())
            return
        }

        if fi, err := os.Stat(filePath); err != nil {
            log.Printf("Error verifying saved file: %v", err)
            c.String(http.StatusInternalServerError, "File verification failed")
            return
        } else {
            log.Printf("File saved successfully, size: %d bytes", fi.Size())
            if fi.Size() < 1024 {
                os.Remove(filePath)
                log.Printf("Removed file due to small size: %d bytes", fi.Size())
                c.String(http.StatusBadRequest, "File too small to be a valid image")
                return
            }
        }

        // Remove metadata
        err = removeMetadata(filePath)
        if err != nil {
            log.Printf("Error removing metadata from %s: %v", anonFilename, err)
        } else {
            log.Printf("Successfully removed metadata from %s", anonFilename)
        }

        // Final verification
        if fi, err := os.Stat(filePath); err != nil {
            log.Printf("Final verification failed: %v", err)
            c.String(http.StatusInternalServerError, "File processing failed")
            return
        } else {
            log.Printf("Final file size: %d bytes", fi.Size())
            if fi.Size() < 1024 {
                os.Remove(filePath)
                log.Printf("Removed file due to small size after processing: %d bytes", fi.Size())
                c.String(http.StatusBadRequest, "File processing resulted in invalid image")
                return
            }
        }

        log.Printf("Successfully processed file %s", anonFilename)
        c.String(http.StatusOK, "Image uploaded successfully")
    })

    // Index handler
    r.GET("/", func(c *gin.Context) {
        files, err := ioutil.ReadDir(uploadDir)
        if err != nil {
            log.Printf("Error reading files directory: %v", err)
            c.String(http.StatusInternalServerError, "Error reading files: "+err.Error())
            return
        }

        var imageFiles []ImageFile
        log.Printf("Found %d files in uploads directory", len(files))

        for _, file := range files {
            if !file.IsDir() {
                if file.Size() < 1024 {
                    log.Printf("Removing invalid file %s (size: %d bytes)", file.Name(), file.Size())
                    os.Remove(filepath.Join(uploadDir, file.Name()))
                    continue
                }
                imageFiles = append(imageFiles, ImageFile{
                    Path:    "/uploads/" + file.Name(),
                    ModTime: file.ModTime(),
                })
                log.Printf("Adding valid image: %s (size: %d bytes, uploaded: %v)",
                    file.Name(), file.Size(), file.ModTime())
            }
        }

        sort.Sort(ByModTime(imageFiles))

        var images []string
        for _, img := range imageFiles {
            images = append(images, img.Path)
        }

        log.Printf("Serving %d valid images", len(images))
        c.HTML(http.StatusOK, "index.html", gin.H{
            "Images": images,
        })
    })

    // Favicon
    r.GET("/favicon.ico", func(c *gin.Context) {
        c.File(filepath.Join(staticDir, "favicon.ico"))
    })

    // Load HTML templates
    templatesDir := filepath.Join(cwd, "templates")
    r.LoadHTMLGlob(filepath.Join(templatesDir, "*"))

    // Start server
    r.Run(":8080")
}
