package integration

import (
	jsonMod "encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"

	_ "github.com/mholt/caddy-l4"
)

func TestCaddyfileAdaptToJSON(t *testing.T) {
	// load the list of test files from the dir
	files, err := os.ReadDir("./caddyfile_adapt")
	if err != nil {
		t.Errorf("failed to read caddyfile_adapt dir: %s", err)
	}

	// prep a regexp to fix strings on Windows
	winNewlines := regexp.MustCompile(`\r?\n`)

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		// read the test file
		filename := f.Name()
		data, err := os.ReadFile("./caddyfile_adapt/" + filename)
		if err != nil {
			t.Errorf("failed to read %s dir: %s", filename, err)
		}

		// split into sections separated by "----------"
		// the last section is always the expected JSON output
		// all preceding sections are Caddyfile variants that must produce the same JSON
		parts := strings.Split(string(data), "----------")
		if len(parts) < 2 {
			t.Errorf("file %s must have at least one Caddyfile and one JSON section separated by '----------'", filename)
			continue
		}

		// last part is the expected JSON
		json := strings.TrimSpace(parts[len(parts)-1])

		// replace windows newlines in the JSON with Unix newlines
		json = winNewlines.ReplaceAllString(json, "\n")

		// replace os-specific default path for file_server's hide field
		replacePath, _ := jsonMod.Marshal(fmt.Sprint(".", string(filepath.Separator), "Caddyfile"))
		json = strings.ReplaceAll(json, `"./Caddyfile"`, string(replacePath))

		// all preceding parts are Caddyfile variants
		caddyfiles := parts[:len(parts)-1]

		for i, caddyfilePart := range caddyfiles {
			// append newline to Caddyfile to match formatter expectations
			caddyfile := strings.TrimSpace(caddyfilePart) + "\n"

			label := filename
			if len(caddyfiles) > 1 {
				label = fmt.Sprintf("%s[%d]", filename, i)
			}

			// run the test
			ok := caddytest.CompareAdapt(t, label, caddyfile, "caddyfile", json)
			if !ok {
				t.Errorf("failed to adapt %s", label)
			}
		}
	}
}
