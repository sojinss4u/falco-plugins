module github.com/sojinss4u/falco-plugins/plugins/k8saudit-eks

go 1.17

require (
	github.com/falcosecurity/plugin-sdk-go v0.7.4
	github.com/sojinss4u/falco-plugins/plugins/k8saudit main
	github.com/sojinss4u/falco-plugins/shared/go/aws/cloudwatchlogs main
	github.com/sojinss4u/falco-plugins/shared/go/aws/session main
	github.com/invopop/jsonschema v0.12.0
)

require (
	github.com/alecthomas/jsonschema v0.0.0-20220216202328-9eeeec9d044b // indirect
	github.com/aws/aws-sdk-go v1.54.3 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/iancoleman/orderedmap v0.3.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
