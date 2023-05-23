package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"

	spinhttp "github.com/fermyon/spin/sdk/go/http"
	"github.com/jpflueger/awesome/blob"
	"golang.org/x/image/draw"
)

const (
	allowedOrigin   = "eventgrid.azure.net"
	sharedAccessKey = "placeholder"
)

func init() {
	spinhttp.Handle(func(w http.ResponseWriter, r *http.Request) {
		log.SetFlags(log.LstdFlags | log.LUTC)

		if !isFromAllowedOrigin(r) {
			http.Error(w, fmt.Sprintf("Request origin '%v' is not allowed", r.Header.Get("WebHook-Request-Origin")), http.StatusForbidden)
			return
		}

		if r.Header.Get("Content-Type") != "application/cloudevents+json; charset=utf-8" {
			http.Error(w, fmt.Sprintf("Content-Type '%v' is not allowed", r.Header.Get("Content-Type")), http.StatusUnsupportedMediaType)
			return
		}

		switch r.Method {
		case "OPTIONS":
			handleAbuseProtection(w, r)
			return
		case "POST":
			handleEvent(w, r)
			return
		default:
			http.Error(w, fmt.Sprintf("Method '%v' is not allowed", r.Method), http.StatusMethodNotAllowed)
			return
		}
	})
}

func main() {}

// event handlers
func handleAbuseProtection(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Allow", "POST")
	w.Header().Set("WebHook-Allowed-Origin", allowedOrigin)
}

func handleEvent(w http.ResponseWriter, r *http.Request) {
	var event CloudEvent[BlobStorageEvent]
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode request body: %v", err), http.StatusBadRequest)
		return
	}

	switch event.Type {
	case StorageBlobCreatedEvent:
		// ignore thumbnails
		// TODO: write thumbnails to a different container
		if strings.Contains(event.Data.Url, "-thumb") {
			log.Printf("Ignoring thumbnail: %v", event.Data.Url)
			w.WriteHeader(http.StatusOK)
		} else {
			handleBlobCreatedEvent(w, &event)
		}
		return
	case StorageBlobDeletedEvent:
		handleBlobDeletedEvent(w, &event)
		return
	case StorageBlobRenamedEvent:
		handleBlobRenamedEvent(w, &event)
		return
	default:
		http.Error(w, fmt.Sprintf("Event type '%v' is not allowed", event.Type), http.StatusBadRequest)
		return
	}
}

func handleBlobCreatedEvent(w http.ResponseWriter, event *CloudEvent[BlobStorageEvent]) {
	log.Printf("Handling blob created: %v", event.Data.Url)
	var err error
	var originalUrl *url.URL
	if originalUrl, err = originalUrl.Parse(event.Data.Url); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse blob url: %v", err), http.StatusInternalServerError)
		return
	}

	urlPathParts := strings.Split(strings.TrimPrefix(originalUrl.Path, "/"), "/")
	container := urlPathParts[0]
	originalBlobName := urlPathParts[1]

	var getOriginalResponse *http.Response

	c := blob.NewBlobClient(sharedAccessKey, originalUrl)
	if getOriginalResponse, err = c.GetBlob(container, originalBlobName); err != nil {
		http.Error(w, fmt.Sprintf("failed to get blob: %v", err), http.StatusInternalServerError)
		return
	}

	if getOriginalResponse.StatusCode != http.StatusOK {
		if errMsgBytes, err := io.ReadAll(getOriginalResponse.Body); err != nil {
			errMsg := fmt.Sprintf("failed to read response body from error response: %v", err)
			log.Printf(errMsg)
			http.Error(w, errMsg, http.StatusInternalServerError)
			return
		} else {
			errMsg := fmt.Sprintf("failed to get blob: %v", string(errMsgBytes))
			log.Printf(errMsg)
			http.Error(w, errMsg, getOriginalResponse.StatusCode)
			return
		}
	}

	originalImage, err := decodeImage(getOriginalResponse)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to decode blob: %v", err), http.StatusInternalServerError)
		return
	}

	// resize the original image into a thumbnail
	thumb := resize(originalImage, image.Point{100, 100})

	// encode the thumbnail into a buffer
	thumbBuf := new(bytes.Buffer)
	if err := jpeg.Encode(thumbBuf, thumb, nil); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode thumbnail: %v", err), http.StatusInternalServerError)
		return
	}

	// upload the thumbnail
	if putBlobResponse, err := c.PutBlob(container, getThumbnailName(originalBlobName), thumbBuf.Bytes(), event.Data.ContentType); err != nil {
		http.Error(w, fmt.Sprintf("Failed to put thumbnail: %v", err), http.StatusInternalServerError)
		return
	} else {
		defer putBlobResponse.Body.Close()
		w.WriteHeader(http.StatusOK)
	}
}

func handleBlobDeletedEvent(w http.ResponseWriter, event *CloudEvent[BlobStorageEvent]) {
	log.Printf("Blob deletion isn't handled yet: %v", event.Data.Url)
	w.WriteHeader(http.StatusNotImplemented)
}

func handleBlobRenamedEvent(w http.ResponseWriter, event *CloudEvent[BlobStorageEvent]) {
	log.Printf("Blob renamed isn't handled yet: %v", event.Data.Url)
	w.WriteHeader(http.StatusNotImplemented)
}

// helpers

func isFromAllowedOrigin(r *http.Request) bool {
	return r.Header.Get("WebHook-Request-Origin") == allowedOrigin
}

func resize(src image.Image, dstSize image.Point) *image.RGBA {
	srcRect := src.Bounds()
	dstRect := image.Rectangle{
		Min: image.Point{0, 0},
		Max: dstSize,
	}
	dst := image.NewRGBA(dstRect)

	//TODO: support configuring the scaling algorithm
	draw.NearestNeighbor.Scale(dst, dstRect, src, srcRect, draw.Over, nil)

	return dst
}

func decodeImage(resp *http.Response) (image.Image, error) {
	var img image.Image
	var err error

	format := resp.Header.Get("Content-Type")
	switch format {
	case "image/jpeg":
		img, err = jpeg.Decode(resp.Body)
		break
	default:
		return nil, fmt.Errorf("Unsupported image format: %v", format)
	}

	if err != nil {
		return nil, fmt.Errorf("Failed to decode blob: %v", err)
	}

	return img, nil
}

func getThumbnailName(name string) string {
	ext := path.Ext(name)
	nameWithoutExt := strings.TrimSuffix(name, ext)
	return nameWithoutExt + "-thumb" + ext
}

// CloudEvent types
type CloudEventType string

const (
	StorageBlobCreatedEvent CloudEventType = "Microsoft.Storage.BlobCreated"
	StorageBlobDeletedEvent CloudEventType = "Microsoft.Storage.BlobDeleted"
	StorageBlobRenamedEvent CloudEventType = "Microsoft.Storage.BlobRenamed"
)

type CloudEvent[T any] struct {
	Id          string         `json:"id"`
	Source      string         `json:"source"`
	SpecVersion string         `json:"specversion"`
	Type        CloudEventType `json:"type"`
	Subject     string         `json:"subject"`
	Time        string         `json:"time"`
	Data        T              `json:"data"`
}

type RawCloudEvent = CloudEvent[json.RawMessage]

type BlobStorageEvent struct {
	Api             string `json:"api"`
	ClientRequestId string `json:"clientRequestId"`
	RequestId       string `json:"requestId"`
	Etag            string `json:"etag"`
	ContentType     string `json:"contentType"`
	ContentLength   int    `json:"contentLength"`
	BlobType        string `json:"blobType"`
	Url             string `json:"url"`
	Sequencer       string `json:"sequencer"`
}
