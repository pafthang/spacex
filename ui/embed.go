// Package ui handles the PocketBase Admin frontend embedding.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distDir embed.FS

// DistDirFS contains the embedded dist directory files (without the "dist" prefix)
var DistDirFS = mustSubFS(distDir, "dist")

// mustSubFS is a helper function to handle subdirectory embedding
func mustSubFS(fsys embed.FS, dir string) fs.FS {
	subFS, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return subFS
}
