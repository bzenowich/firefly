// Package web embeds the templates and static assets so fwd ships as a
// single binary.
package web

import "embed"

//go:embed templates static
var FS embed.FS
