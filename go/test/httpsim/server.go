package httpsim

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

var (
	urlRe    = regexp.MustCompile(`(?m)^(GET|POST|PUT)[ ]+(\S*)[ ]*\n`)
	statusRe = regexp.MustCompile(`^\d{3}[ ]*\n`)
)

/*
NewTLSServer creates a new httptest.Server from an input text.
Input text has multiple blocks.
Each block is starting with a line GET|POST|PUT <URL>.
It follows an optional status code which defaults to 200.
Then follow optional header lines marked with "H: ".
Remaining lines are used as response body.
Path and query param of each URL line are fed as pattern to mux.NewRouter.
Method pathPrefix is used to match path param.

Special case:
If body is single line "EOF", the client connection is closed prematurely.

Example:

GET /hello
hello world
POST /api?type=keygen
200
H: Content-Type application/json
{"key": "value"}
GET /failure
EOF
*/
func NewTLSServer(t *testing.T, input string) *httptest.Server {
	var server *httptest.Server
	router := mux.NewRouter()
	il := urlRe.FindAllStringSubmatchIndex(input, -1)
	if il == nil || il[0][0] != 0 {
		t.Fatal("Missing 'GET|POST|PUT url' in first line")
	}
	for i, p := range il {
		method := input[p[2]:p[3]]
		// Parse URL into path and query parameters.
		uri := input[p[4]:p[5]]
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("%v", err)
		}
		var kvPairs []string
		values := u.Query()
		for k := range values {
			kvPairs = append(kvPairs, k, values.Get(k))
		}
		// Find body with optionally preceeding status and headers.
		start := p[1]
		end := len(input)
		if i+1 < len(il) {
			end = il[i+1][0]
		}
		body := input[start:end]
		statStr := "200"
		if l := statusRe.FindStringIndex(body); l != nil {
			statStr = strings.TrimSpace(body[l[0]:l[1]])
			body = body[l[1]:]
		}
		status, _ := strconv.Atoi(statStr)

		// Add route for found URL and query parameters.
		r := router.NewRoute()
		r.Methods(method).PathPrefix(u.Path)
		r.Queries(kvPairs...)
		r.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				for {
					if line, b, ok := strings.Cut(body, "\n"); ok {
						if l := strings.Fields(line); len(l) == 3 && l[0] == "H:" {
							w.Header().Set(l[1], l[2])
							body = b
							continue
						}
					}
					break
				}
				if body == "EOF\n" {
					server.CloseClientConnections()
					return
				}
				w.WriteHeader(status)
				w.Write([]byte(body))
			})
	}
	server = httptest.NewTLSServer(router)
	return server
}
