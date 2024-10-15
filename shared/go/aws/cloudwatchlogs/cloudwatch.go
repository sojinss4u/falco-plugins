// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

package cloudwatchlogs

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
)

const (
	DefaultShift            time.Duration = 1 * time.Second // controls the time shift in past for the first call to CloudwatchLogs API
	DefaultPollingInterval  time.Duration = 5 * time.Second // time between two calls to CloudwatchLogs API
	DefaultBufferSize       uint64        = 200             // buffer size of the channel that transmits Logs to the Plugin
	QueryResultPollInterval time.Duration = 5 * time.Second // time to wait before checking the cloudwatch insight query result
)

// Filter represents a filter for retrieving logs from CloudwatchLogs API
type Filter struct {
	FilterPattern       string
	LogGroupName        string
	LogStreamNamePrefix string
	LogStreamNames      []string
}

// Client represents a client for CloudwatchLogs API
type Client struct {
	*cloudwatchlogs.CloudWatchLogs
}

// Options represents options for calls to CloudwatchLogs API
type Options struct {
	Shift           time.Duration
	PollingInterval time.Duration
	BufferSize      uint64
}

// CreateOptions returns Options for retrieving logs from CloudwatchLogs API
func CreateOptions(shift, pollingInterval time.Duration, bufferSize uint64) *Options {
	options := new(Options)
	options.Shift = shift
	options.PollingInterval = pollingInterval
	options.BufferSize = bufferSize
	options.setDefault()
	return options
}

// setDefault set the default values for Options
func (options *Options) setDefault() {
	if options.Shift == 0 {
		options.Shift = DefaultShift
	}
	if options.PollingInterval == 0 {
		options.PollingInterval = DefaultPollingInterval
	}
	if options.BufferSize == 0 {
		options.BufferSize = DefaultBufferSize
	}
}

// CreateFilter returns a Client for retrieving logs from CloudwatchLogs API
func CreateFilter(filterPattern, logGroupName, logStreamNamePrefix string, logStreamNames []string) *Filter {
	if logStreamNamePrefix == "" {
		logStreamNamePrefix = "*"
	}

	return &Filter{
		FilterPattern:       filterPattern,
		LogGroupName:        logGroupName,
		LogStreamNamePrefix: logStreamNamePrefix,
		LogStreamNames:      logStreamNames,
	}
}

// CreateFilter returns a Filter for CloudwatchLogs API
func CreateClient(sess *session.Session, cfgs *aws.Config) *Client {
	return &Client{
		CloudWatchLogs: cloudwatchlogs.New(sess, cfgs),
	}
}

// This function uses CloudWatch Query Insights Instead of filter log events to retrieve cloudwatch logs

func (client *Client) Open(context context.Context, filter *Filter, options *Options) (chan *cloudwatchlogs.FilteredLogEvent, chan error) {
	if options == nil {
		options = new(Options)
		options.setDefault()
	}

	queryString := `
        fields @timestamp, @message, @ptr | filter @message like /audit/
		`

	fmt.Println("Inside CloudWatch Open Function")

	// Create input for StartQuery
	queryInput := &cloudwatchlogs.StartQueryInput{
		StartTime:    aws.Int64(time.Now().Add(-1 * options.Shift).Unix()), // Set start time to (current time - shift) seconds
		EndTime:      aws.Int64(time.Now().Unix()),                         // Set end time to current time
		LogGroupName: aws.String(filter.LogGroupName),                      // Log group to query
		QueryString:  aws.String(queryString),                              // Query string
	}

	eventC := make(chan *cloudwatchlogs.FilteredLogEvent, options.BufferSize)
	errC := make(chan error)

	var nextStartTime int64

	go func() {
		defer close(eventC)
		defer close(errC)
		fmt.Println("Starting Query ..")
		fmt.Println("Entering for loop ..")
		for {
			fmt.Println("Inside For Loop")
			// Update the start time if there's a last event time
			if nextStartTime > 0 {
				currentTime := time.Now().Unix()
				timeDiff := (currentTime - nextStartTime)
				// Adding a protection here so that the query will not keep querying same time range again & increase cost in case of any issues
				if timeDiff > 600 {
					queryInput.StartTime = aws.Int64(time.Now().Add(-1 * options.Shift).Unix())
					queryInput.EndTime = aws.Int64(time.Now().Unix())
				} else {
					queryInput.StartTime = aws.Int64(nextStartTime)
					queryInput.EndTime = aws.Int64(time.Now().Unix())
				}
			}

			fmt.Println(*queryInput.StartTime)
			fmt.Println(*queryInput.EndTime)

			// Start the query
			startQueryOutput, err := client.CloudWatchLogs.StartQuery(queryInput)
			if err != nil {
				fmt.Println(err)
				errC <- err
				return
			}
			fmt.Println("Started Query")
			queryID := *startQueryOutput.QueryId

			fmt.Println(queryID)

			// Create the input for GetQueryResults outside the loop
			getQueryResultsInput := &cloudwatchlogs.GetQueryResultsInput{
				QueryId: aws.String(queryID),
			}

			// Poll for query results
			var queryCompleted bool
			for !queryCompleted {
				// Sleep before checking the query result again
				time.Sleep(QueryResultPollInterval)

				// Retrieve query results
				queryResults, err := client.CloudWatchLogs.GetQueryResults(getQueryResultsInput)
				if err != nil {
					errC <- err
					return
				}

				// Check the status of the query
				if *queryResults.Status == "Complete" {
					queryCompleted = true
					// Process the query results only if the query is complete
					for _, result := range queryResults.Results {
						var timestamp, message, ptr string
						// Extract fields from each result
						for _, field := range result {
							switch *field.Field {
							case "@timestamp":
								timestamp = *field.Value
							case "@message":
								message = *field.Value
							case "@ptr":
								ptr = *field.Value
							}
						}

						// Create a new FilteredLogEvent and populate the fields
						parsedTimestamp := parseTimestampToMillis(timestamp)
						filteredLogEvent := &cloudwatchlogs.FilteredLogEvent{
							EventId:       aws.String(ptr),
							IngestionTime: aws.Int64(time.Now().UnixMilli()), // Use current time as ingestion time
							LogStreamName: aws.String(filter.LogGroupName),   // Use log group name as log stream
							Message:       aws.String(message),
							Timestamp:     aws.Int64(parsedTimestamp),
						}

						// Send the formatted event to the event channel
						eventC <- filteredLogEvent

					}
				}
			}
			nextStartTime = *queryInput.EndTime + 1
			// Wait for the polling interval before the next loop
			time.Sleep(options.PollingInterval)
		}
	}()
	return eventC, errC
}

// parseTimestampToMillis converts a timestamp string to milliseconds since Unix epoch
func parseTimestampToMillis(timestamp string) int64 {
	// Parse the timestamp in "yyyy-MM-dd HH:mm:ss.SSS" format
	t, err := time.Parse("2006-01-02 15:04:05.000", timestamp)
	if err != nil {
		// If parsing fails, return the current time in milliseconds
		return time.Now().UnixMilli()
	}
	return t.UnixNano() / int64(time.Millisecond)
}

// Open returns an instance with the functionn called to retrieve logs
/*func (client *Client) OpenFilterLogEvents(context context.Context, filter *Filter, options *Options) (chan *cloudwatchlogs.FilteredLogEvent, chan error) {
	if options == nil {
		options = new(Options)
		options.setDefault()
	}

	filters := &cloudwatchlogs.FilterLogEventsInput{
		StartTime:           aws.Int64(time.Now().Add(-1 * options.Shift).UnixMilli()),
		FilterPattern:       aws.String(filter.FilterPattern),
		LogGroupName:        aws.String(filter.LogGroupName),
		LogStreamNamePrefix: aws.String(filter.LogStreamNamePrefix),
	}

	if len(filter.LogStreamNamePrefix) == 0 {
		filters.LogStreamNames = aws.StringSlice(filter.LogStreamNames)
	}

	eventC := make(chan *cloudwatchlogs.FilteredLogEvent, options.BufferSize)
	errC := make(chan error)

	go func() {
		defer close(eventC)
		defer close(errC)
		for {
			var lastEventTime int64
			err := client.CloudWatchLogs.FilterLogEventsPagesWithContext(aws.Context(context), filters,
				func(page *cloudwatchlogs.FilterLogEventsOutput, lastPage bool) bool {
					if len(page.Events) == 0 {
						return false
					}
					for _, i := range page.Events {
						eventC <- i
						if lastEventTime < *i.Timestamp {
							lastEventTime = *i.Timestamp
						}
					}
					return true
				})
			if err != nil {
				errC <- err
				return
			}

			time.Sleep(options.PollingInterval)
			if lastEventTime > 0 {
				filters.SetStartTime(lastEventTime + 1)
			}
		}
	}()
	return eventC, errC
}*/
