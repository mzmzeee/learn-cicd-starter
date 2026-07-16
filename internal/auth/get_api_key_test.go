package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantError error
	}{
		{
			name:      "valid api key",
			headers:   http.Header{"Authorization": []string{"ApiKey my-secret-key-123"}},
			wantKey:   "my-secret-key-123",
			wantError: nil,
		},
		{
			name:      "no authorization header",
			headers:   http.Header{},
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "malformed - no space",
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:   "",
			wantError: ErrMalformedAuthHeader,
		},
		{
			name:      "malformed - wrong prefix",
			headers:   http.Header{"Authorization": []string{"Bearer token123"}},
			wantKey:   "",
			wantError: ErrMalformedAuthHeader,
		},
		{
			name:      "malformed - empty value after prefix",
			headers:   http.Header{"Authorization": []string{"ApiKey "}},
			wantKey:   "",
			wantError: nil,
		},
		{
			name:      "malformed - extra segments",
			headers:   http.Header{"Authorization": []string{"ApiKey key1 key2"}},
			wantKey:   "key1",
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}

			if tt.wantError != nil {
				if gotErr == nil {
					t.Errorf("GetAPIKey() error = nil, want %v", tt.wantError)
					return
				}
				if gotErr.Error() != tt.wantError.Error() {
					t.Errorf("GetAPIKey() error = %q, want %q", gotErr.Error(), tt.wantError.Error())
				}
			} else {
				if gotErr != nil {
					t.Errorf("GetAPIKey() error = %q, want nil", gotErr.Error())
				}
			}
		})
	}
}
