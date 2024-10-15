// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package k8sauditeks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	"github.com/sojinss4u/falco-plugins/plugins/k8saudit/pkg/k8saudit"
	"github.com/sojinss4u/falco-plugins/shared/go/aws/cloudwatchlogs"
	"github.com/sojinss4u/falco-plugins/shared/go/aws/session"
	"github.com/invopop/jsonschema"
)

const pluginName = "k8saudit-eks"
const regExpAuditID = `"auditID":[ a-z0-9-"]+`

var regExpCAuditID *regexp.Regexp

type Plugin struct {
	k8saudit.Plugin
	Logger *log.Logger
	Config PluginConfig
}

type PluginConfig struct {
	Profile         string `json:"profile"          jsonschema:"title=profile,description=The Profile to use to create the session, env var AWS_PROFILE if present"`
	Region          string `json:"region"           jsonschema:"title=region,description=The Region of your EKS cluster, env var AWS_REGION is used if present"`
	BufferSize      uint64 `json:"buffer_size"      jsonschema:"title=buffer_size,description=Buffer Size (default: 200),default=200"`
	Shift           uint64 `json:"shift"            jsonschema:"title=shift,description=Time shift in past in seconds (default: 1s),default=1"`
	PollingInterval uint64 `json:"polling_interval" jsonschema:"title=polling_interval,description=Polling Interval in seconds (default: 5s),default=5"`
	UseAsync        bool   `json:"use_async"        jsonschema:"title=use_async,description=If true then async extraction optimization is enabled (default: true),default=true"`
}

func (k *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          9,
		Name:        pluginName,
		Description: "Read Kubernetes Audit Events for EKS from Cloudwatch Logs",
		Contact:     "github.com/falcosecurity/plugins",
		Version:     "0.5.1",
		EventSource: "k8s_audit",
	}
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {
	if i := os.Getenv("AWS_DEFAULT_PROFILE"); i != "" {
		p.Profile = i
	}
	if i := os.Getenv("AWS_PROFILE"); i != "" {
		p.Profile = i
	}
	if i := os.Getenv("AWS_DEFAULT_REGION"); i != "" {
		p.Region = i
	}
	if i := os.Getenv("AWS_REGION"); i != "" {
		p.Region = i
	}
	p.UseAsync = true
	// for PollingInterval, Shift and BufferSize, the default values from the package are used automatically
}

func (k *Plugin) Init(cfg string) error {
	// read configuration
	k.Plugin.Config.Reset()
	k.Config.Reset()

	err := json.Unmarshal([]byte(cfg), &k.Config)
	if err != nil {
		return err
	}

	regExpCAuditID, err = regexp.Compile(regExpAuditID)
	if err != nil {
		return err
	}

	// setup optional async extraction optimization
	extract.SetAsync(k.Config.UseAsync)

	k.Logger = log.New(os.Stderr, "["+pluginName+"] ", log.LstdFlags|log.LUTC|log.Lmsgprefix)

	return nil
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		// all properties are optional by default
		RequiredFromJSONSchemaTags: true,
		// unrecognized properties don't cause a parsing failures
		AllowAdditionalProperties: true,
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (p *Plugin) OpenParams() ([]sdk.OpenParam, error) {
	return []sdk.OpenParam{
		{Value: "default", Desc: "Cluster Name"},
	}, nil
}

func (p *Plugin) Open(clustername string) (source.Instance, error) {
	if clustername == "" {
		return nil, fmt.Errorf("cluster name can't be empty")
	}
	filter := cloudwatchlogs.CreateFilter("", "/aws/eks/"+clustername+"/cluster", "kube-apiserver-audit", nil)
	client := cloudwatchlogs.CreateClient(session.CreateSession(p.Config.Region, p.Config.Profile), nil)
	ctx, cancel := context.WithCancel(context.Background())
	options := cloudwatchlogs.CreateOptions(
		time.Duration(p.Config.Shift) * time.Second,
	    time.Duration(p.Config.PollingInterval) * time.Second,
		p.Config.BufferSize,
	)
	eventsC, errC := client.Open(ctx, filter, options)
	pushEventC := make(chan source.PushEvent)
	go func() {
		for {
			select {
			case i := <-eventsC:
                                //message := `{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"0e31d044-ea7f-4ca2-8034-ee0f543acd44","stage":"ResponseStarted","requestURI":"/api/v1/namespaces/traefik-v2-flux/pods/traefik-concierge-5556b9d544-8tcvp/exec?command=%2Fbin%2Fsh\u0026container=web\u0026stdin=true\u0026stdout=true\u0026tty=true","verb":"create","user":{"username":"soji.antony@razorpay.com","groups":["39630c45-9625-4d17-874a-b2630c02a943","08a9114c-6931-4038-b2bf-8e12585ecb8f","811f79b0-99b2-43f0-acfb-e2513dfc1559","system:authenticated"]},"sourceIPs":["115.110.224.178"],"userAgent":"kubectl/v1.30.0 (darwin/amd64) kubernetes/7c48c2b","objectRef":{"resource":"pods","namespace":"traefik-v2-flux","name":"traefik-concierge-5556b9d544-8tcvp","apiVersion":"v1","subresource":"exec"},"responseStatus":{"metadata":{},"code":101},"requestReceivedTimestamp":"2024-10-14T04:58:30.365903Z","stageTimestamp":"2024-10-14T04:58:30.386617Z","annotations":{"authorization.k8s.io/decision":"allow","authorization.k8s.io/reason":"RBAC: allowed by ClusterRoleBinding \"admin-binding\" of ClusterRole \"cluster-admin\" to User \"soji.antony@razorpay.com\""}}`
				message := *i.Message
				if strings.HasSuffix(message, "[Truncated...]") {
					auditID := regExpCAuditID.FindStringSubmatch(message)
					if len(auditID) > 0 {
						p.Logger.Printf("truncated log line, can't be parsed (%v)\n", auditID[0])
					} else {
						p.Logger.Println("truncated log line, can't be parsed")
					}
					continue
				}
				values, err := p.Plugin.ParseAuditEventsPayload([]byte(*i.Message))
				if err != nil {
					p.Logger.Println(err)
					continue
				}
				for _, j := range values {
					if j.Err != nil {
						p.Logger.Println(j.Err)
						continue
					}
					pushEventC <- *j
				}
			case e := <-errC:
				pushEventC <- source.PushEvent{Err: e}
				// errors are blocking, so we can stop here
				return
			}
		}
	}()
	return source.NewPushInstance(
		pushEventC,
		source.WithInstanceClose(cancel),
	)
}
