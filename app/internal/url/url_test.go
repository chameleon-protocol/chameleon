package url

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	type args struct {
		rawURL string
	}
	tests := []struct {
		name    string
		args    args
		want    *URL
		wantErr bool
	}{
		{
			name: "no port",
			args: args{
				rawURL: "chameleon://ganggang@icecreamsogood/",
			},
			want: &URL{
				Scheme: "chameleon",
				User:   User("ganggang"),
				Host:   "icecreamsogood",
				Path:   "/",
			},
		},
		{
			name: "single port",
			args: args{
				rawURL: "chameleon://yesyes@icecreamsogood:8888/",
			},
			want: &URL{
				Scheme: "chameleon",
				User:   User("yesyes"),
				Host:   "icecreamsogood:8888",
				Path:   "/",
			},
		},
		{
			name: "multi port",
			args: args{
				rawURL: "chameleon://darkness@laplus.org:8888,9999,11111/",
			},
			want: &URL{
				Scheme: "chameleon",
				User:   User("darkness"),
				Host:   "laplus.org:8888,9999,11111",
				Path:   "/",
			},
		},
		{
			name: "range port",
			args: args{
				rawURL: "chameleon://darkness@laplus.org:8888-9999/",
			},
			want: &URL{
				Scheme: "chameleon",
				User:   User("darkness"),
				Host:   "laplus.org:8888-9999",
				Path:   "/",
			},
		},
		{
			name: "both",
			args: args{
				rawURL: "chameleon://gawr:gura@atlantis.moe:443,7788-8899,10010/",
			},
			want: &URL{
				Scheme: "chameleon",
				User:   UserPassword("gawr", "gura"),
				Host:   "atlantis.moe:443,7788-8899,10010",
				Path:   "/",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args.rawURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() got = %v, want %v", got, tt.want)
			}
		})
	}
}
