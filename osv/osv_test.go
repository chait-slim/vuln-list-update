package osv_test

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/osv"
)

func Test_Update(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		ecosystem map[string]string
		wantFiles []string
		wantErr   string
	}{
		{
			name: "happy path python",
			ecosystem: map[string]string{
				"PyPI": "python",
			},
			wantFiles: []string{
				filepath.Join("python", "cherrypy", "PYSEC-2006-1.json"),
				filepath.Join("python", "trac", "PYSEC-2005-1.json"),
				filepath.Join("python", "trac", "PYSEC-2006-2.json"),
				filepath.Join("python", "aiohttp", "PYSEC-2023-120.json"),
			},
		},
		{
			name: "happy path Go",
			ecosystem: map[string]string{
				"Go": "go",
			},
			wantFiles: []string{
				filepath.Join("go", "github.com", "gin-gonic", "gin", "GO-2020-0001.json"),
				filepath.Join("go", "github.com", "seccomp", "libseccomp-golang", "GO-2020-0007.json"),
				filepath.Join("go", "github.com", "tidwall", "gjson", "GO-2021-0059.json"),
			},
		},
		{
			name: "happy path python+rust",
			ecosystem: map[string]string{
				"PyPI":      "python",
				"crates.io": "rust",
			},
			wantFiles: []string{
				// Python
				filepath.Join("python", "cherrypy", "PYSEC-2006-1.json"),
				filepath.Join("python", "trac", "PYSEC-2005-1.json"),
				filepath.Join("python", "trac", "PYSEC-2006-2.json"),

				// Rust
				filepath.Join("rust", "openssl", "RUSTSEC-2016-0001.json"),
				filepath.Join("rust", "smallvec", "RUSTSEC-2019-0009.json"),
				filepath.Join("rust", "tar", "RUSTSEC-2018-0002.json"),
			},
		},
		{
			name: "sad path, unable to download archive",
			path: "/%s/unknown.zip",
			ecosystem: map[string]string{
				"PyPI": "python",
			},
			wantErr: "bad response code: 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			for name, dir := range tt.ecosystem {
				b, err := os.ReadFile(filepath.Join("testdata", dir, "all.zip"))
				require.NoError(t, err)
				mux.HandleFunc(fmt.Sprintf("/%s/all.zip", name), func(w http.ResponseWriter, r *http.Request) {
					_, err = w.Write(b)
					require.NoError(t, err)
				})
			}
			ts := httptest.NewServer(mux)

			defer ts.Close()

			// build test settings
			testDir := t.TempDir()
			testURL := ts.URL + "/%s/all.zip"
			if tt.path != "" {
				testURL = ts.URL + tt.path
				fmt.Println(testURL)
			}

			c := osv.NewOsv(osv.WithURL(testURL), osv.WithDir(testDir), osv.WithEcosystem(tt.ecosystem))

			err := c.Update()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)

			for _, wantFile := range tt.wantFiles {
				got, err := os.ReadFile(filepath.Join(testDir, wantFile))
				require.NoError(t, err)

				want, err := os.ReadFile(filepath.Join("testdata", "golden", wantFile))
				require.NoError(t, err)

				assert.JSONEq(t, string(want), string(got))
			}
		})
	}
}

func Test_Update_Root(t *testing.T) {
	// Build all.zip in memory with test advisories
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	advisories := []struct {
		filename string
		content  string
	}{
		{
			filename: "ROOT-OS-ALPINE-318-CVE-2023-38473.json",
			content:  `{"schema_version":"1.6.0","id":"ROOT-OS-ALPINE-318-CVE-2023-38473","upstream":["CVE-2023-38473"],"affected":[{"package":{"name":"rootio-curl","ecosystem":"Alpine"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"7.88.1-r1.root.io.1"}]}]}],"database_specific":{"source":"Root","distro":"alpine","distro_version":"3.18"}}`,
		},
		{
			filename: "ROOT-APP-NPM-CVE-2023-5678.json",
			content:  `{"schema_version":"1.6.0","id":"ROOT-APP-NPM-CVE-2023-5678","upstream":["CVE-2023-5678"],"affected":[{"package":{"name":"@rootio/axios","ecosystem":"npm"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.6.0.root.io.1"}]}]}],"database_specific":{"source":"Root","distro":"","distro_version":""}}`,
		},
		{
			// Empty affected — must be skipped without panic
			filename: "ROOT-OS-ALPINE-318-CVE-2099-EMPTY.json",
			content:  `{"schema_version":"1.6.0","id":"ROOT-OS-ALPINE-318-CVE-2099-EMPTY","upstream":["CVE-2099-99999"],"affected":[],"database_specific":{"source":"Root"}}`,
		},
	}

	for _, adv := range advisories {
		f, err := zw.Create(adv.filename)
		require.NoError(t, err)
		_, err = f.Write([]byte(adv.content))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	defer ts.Close()

	testDir := t.TempDir()
	db := osv.NewOsv(
		osv.WithURL(ts.URL+"/all.zip"), // complete URL — no %s
		osv.WithDir(testDir),
		osv.WithEcosystem(map[string]string{"Root": ""}),
	)

	require.NoError(t, db.Update())

	// OS advisory: <package>/<id>.json
	content, err := os.ReadFile(filepath.Join(testDir, "rootio-curl", "ROOT-OS-ALPINE-318-CVE-2023-38473.json"))
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"schema_version":"1.6.0","id":"ROOT-OS-ALPINE-318-CVE-2023-38473","upstream":["CVE-2023-38473"],"affected":[{"package":{"name":"rootio-curl","ecosystem":"Alpine"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"7.88.1-r1.root.io.1"}]}]}],"database_specific":{"source":"Root","distro":"alpine","distro_version":"3.18"}}`,
		string(content),
	)

	// npm advisory: @rootio/axios produces two-level nesting
	content, err = os.ReadFile(filepath.Join(testDir, "@rootio", "axios", "ROOT-APP-NPM-CVE-2023-5678.json"))
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"schema_version":"1.6.0","id":"ROOT-APP-NPM-CVE-2023-5678","upstream":["CVE-2023-5678"],"affected":[{"package":{"name":"@rootio/axios","ecosystem":"npm"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.6.0.root.io.1"}]}]}],"database_specific":{"source":"Root","distro":"","distro_version":""}}`,
		string(content),
	)

	// Empty affected entry must produce no file anywhere in the output tree
	err = filepath.WalkDir(testDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		assert.NotEqual(t, "ROOT-OS-ALPINE-318-CVE-2099-EMPTY.json", d.Name(),
			"empty-affected advisory should not be written")
		return nil
	})
	require.NoError(t, err)
}
