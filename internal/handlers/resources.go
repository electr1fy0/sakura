package handlers

import (
	"net/http"
	"sakura/internal/utils"
)

func (h *Handler) Protected(w http.ResponseWriter, r *http.Request) {
	utils.WriteJson(w, "you are in my guy")
}
