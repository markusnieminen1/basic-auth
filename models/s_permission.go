package models

type Permission struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
}
