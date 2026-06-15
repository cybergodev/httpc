// Package types provides shared type definitions used across the httpc library.
// This package eliminates interface duplication between public and internal layers,
// enabling compile-time type checking without runtime type assertions.
package types

// FormData represents multipart form data for HTTP requests.
// It contains both text fields and file uploads.
//
// Example:
//
//	form := &types.FormData{
//	    Fields: map[string]string{
//	        "username": "john",
//	        "email": "john@example.com",
//	    },
//	    Files: map[string]*types.FileData{
//	        "avatar": {
//	            Filename:    "avatar.png",
//	            Content:     imageData,
//	            ContentType: "image/png",
//	        },
//	    },
//	}
//	client.Post("/upload", httpc.WithFormData(form))
type FormData struct {
	// Fields contains the text form fields.
	Fields map[string]string
	// Files contains the file uploads mapped by field name.
	Files map[string]*FileData
}

// FileData represents a file to be uploaded in a multipart form.
// It contains the filename, file content, and content type.
type FileData struct {
	// Filename is the name of the file as sent to the server.
	Filename string
	// Content is the raw file content.
	Content []byte
	// ContentType is the MIME type of the file (e.g., "image/png", "application/pdf").
	ContentType string
}
