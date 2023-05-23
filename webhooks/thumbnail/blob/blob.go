package blob

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	spinhttp "github.com/fermyon/spin/sdk/go/http"
)

// Blob Storage REST API
type BlobClient struct {
	sharedAccessKey string
	signingKey      []byte

	account string

	serviceSuffix     string
	serviceApiVersion string
}

func NewBlobClient(sharedAccessKey string, url *url.URL) *BlobClient {
	serviceSuffix := ".blob.core.windows.net"
	serviceApiVersion := "2022-11-02"

	account := strings.TrimSuffix(url.Hostname(), serviceSuffix)

	sharedAccessKeyDecoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(sharedAccessKey))
	var signingKey []byte
	var err error
	if signingKey, err = ioutil.ReadAll(sharedAccessKeyDecoder); err != nil {
		log.Fatalf("failed to read base64 decoded shared access key: %v", err)
	}

	return &BlobClient{
		sharedAccessKey:   sharedAccessKey,
		signingKey:        signingKey,
		account:           account,
		serviceSuffix:     serviceSuffix,
		serviceApiVersion: serviceApiVersion,
	}
}

func (c *BlobClient) GetBlob(container string, blob string) (*http.Response, error) {
	url := fmt.Sprintf("https://%s%s/%s/%s", c.account, c.serviceSuffix, container, blob)

	log.Printf("getting blob: %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for Blob service: %v", err)
	}

	if err := c.addRequiredHeaders(req, container, blob); err != nil {
		return nil, fmt.Errorf("failed to add required headers to request for Blob service: %v", err)
	}

	var response *http.Response
	if response, err = spinhttp.Send(req); err != nil {
		return nil, fmt.Errorf("failed to send request to Blob service: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		if errMsgBytes, err := io.ReadAll(response.Body); err != nil {
			errMsg := fmt.Sprintf("failed to read response body from error response: %v", err)
			log.Printf(errMsg)
			return nil, fmt.Errorf(errMsg)
		} else {
			errMsg := fmt.Sprintf("azure blob rest api returned error: %v %v", response.StatusCode, string(errMsgBytes))
			log.Printf(errMsg)
			return nil, fmt.Errorf(errMsg)
		}
	} else {
		return response, nil
	}
}

func (c *BlobClient) PutBlob(container string, blob string, content []byte, contentType string) (*http.Response, error) {
	url := fmt.Sprintf("https://%s%s/%s/%s", c.account, c.serviceSuffix, container, blob)
	reader := bytes.NewReader(content)

	log.Printf("putting blob: %s", url)

	req, err := http.NewRequest("PUT", url, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for Blob service: %v", err)
	}

	if err := c.addRequiredHeaders(req, container, blob); err != nil {
		return nil, fmt.Errorf("failed to add required headers to request for Blob service: %v", err)
	}

	var response *http.Response
	if response, err = spinhttp.Send(req); err != nil {
		return nil, fmt.Errorf("failed to send request to Blob service: %v", err)
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		if errMsgBytes, err := io.ReadAll(response.Body); err != nil {
			errMsg := fmt.Sprintf("failed to read response body from error response: %v", err)
			log.Printf(errMsg)
			return nil, fmt.Errorf(errMsg)
		} else {
			errMsg := fmt.Sprintf("azure blob rest api returned error: %v %v", response.StatusCode, string(errMsgBytes))
			log.Printf(errMsg)
			return nil, fmt.Errorf(errMsg)
		}
	} else {
		return response, nil
	}
}

func (c *BlobClient) addRequiredHeaders(req *http.Request, container string, blob string) error {
	date := time.Now()
	req.Header.Set("X-Ms-Blob-Type", "BlockBlob")
	req.Header.Set("X-Ms-Date", date.Format(http.TimeFormat))

	if sig, err := c.buildSignature(container, blob, req.Header, req.Method); err != nil {
		return fmt.Errorf("failed to build signature for Blob request: %v", err)
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("SharedKey %s:%s", c.account, sig))
		return nil
	}
}

// adds the required headers to the request
// see: https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
// todo: add support for shared access signatures https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas#version-2020-12-06-and-later
func (c *BlobClient) buildSignature(container string, blob string, headers map[string][]string, method string) (string, error) {

	var canonicalizedHeaders string
	for k, v := range headers {
		if strings.HasPrefix(k, "X-Ms-") {
			canonicalizedHeaders += fmt.Sprintf("%s:%s\n", strings.ToLower(k), v[0])
		}
	}

	// for some reason this seems to work with fewer newlines than the docs specify
	signature := strings.ToUpper(method) + "\n" +
		"\n" +
		"\n" +
		"\n" +
		canonicalizedHeaders +
		fmt.Sprintf("/%s/%s/%s", c.account, container, blob)

	// based on Azure docs, we need to perform this signing for shared key authorization
	// Signature=Base64(HMAC-SHA256(UTF8(StringToSign), Base64.decode(<your_azure_storage_account_shared_key>)))

	hash := hmac.New(sha256.New, c.signingKey)

	if _, err := hash.Write([]byte(signature)); err != nil {
		return "", fmt.Errorf("failed to write signature to hash for Blob request: %v", err)
	}

	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}
