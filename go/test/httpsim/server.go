package httpsim

import (
	"cmp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var (
	urlRe    = regexp.MustCompile(`(?m)^(GET|POST|PUT|DELETE)[ ]+(\S*)[ ]*\n`)
	statusRe = regexp.MustCompile(`^\d{3}[ ]*\n`)
)

/*
NewTLSServer creates a new httptest.Server.
The input text describes the behaviour of this server,
which has multiple blocks.
Each block is starting with a line GET|POST|PUT|DELETE <URL>.
The URL may contain query parameters.
These are used to match
- query parameters of GET requests and
- form data of POST requests.

The lines that follow describe the returned result:
- An optional status code which defaults to 200.
- Optional header lines marked with "H: ".
- Remaining lines are used as response body.

Special case:
If body is single line "EOF", the client connection is closed prematurely.

Example:

GET /hello?name=abc
hello abc
POST /api/?type=keygen
200
H: Content-Type application/json
{"key": "value"}
GET /failure
EOF
*/
func NewTLSServer(t *testing.T, input string) *httptest.Server {
	var server *httptest.Server
	mux := http.NewServeMux()
	il := urlRe.FindAllStringSubmatchIndex(input, -1)
	if il == nil || il[0][0] != 0 {
		t.Fatal("Missing 'GET|POST|PUT|DELETE url' in first line")
	}
	type match struct {
		query url.Values
		size  int
		body  string
	}
	m := make(map[string][]*match)
	for i, p := range il {
		method := input[p[2]:p[3]]
		// Parse URL into path and query parameters.
		uri := input[p[4]:p[5]]
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("URL: %v", err)
		}
		// Find body with optionally preceeding status and headers.
		start := p[1]
		end := len(input)
		if i+1 < len(il) {
			end = il[i+1][0]
		}
		body := input[start:end]
		// Store expected GET or POST form parameters.
		qu := u.Query()
		sz := 0
		for _, l := range qu {
			sz += len(l)
		}
		e := &match{
			size:  sz,
			query: qu,
			body:  body,
		}
		pattern := method + " " + u.Path
		m[pattern] = append(m[pattern], e)
	}
	for pattern, l := range m {
		// Check largest number of params first, to check most specific first.
		slices.SortFunc(l, func(a, b *match) int {
			return cmp.Compare(b.size, a.size)
		})
		// Add route for found pattern from method and path.
		mux.HandleFunc(pattern,
			func(w http.ResponseWriter, r *http.Request) {
				r.ParseForm()
			MATCH:
				for _, e := range l {
					for k := range e.query {
						if r.Form.Get(k) != e.query.Get(k) {
							continue MATCH
						}
					}
					body := e.body
					status := 200
					if l := statusRe.FindStringIndex(body); l != nil {
						statStr := strings.TrimSpace(body[l[0]:l[1]])
						body = body[l[1]:]
						status, _ = strconv.Atoi(statStr)
					}
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
					return
				}
				http.NotFoundHandler().ServeHTTP(w, r)
			})
	}
	server = httptest.NewTLSServer(mux)
	return server
}
