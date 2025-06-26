/*
Copyright 2025 the Unikorn Authors.

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

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/client-go/pkg/tokenrotator"

	"k8s.io/klog/v2"

	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func main() {
	// Do flag parsing.
	zapOptions := &zap.Options{}
	zapOptions.BindFlags(flag.CommandLine)

	rotator := tokenrotator.New()
	rotator.AddFlags(pflag.CommandLine)

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()

	// Do log initialization.
	logr := zap.New(zap.UseFlagOptions(zapOptions))

	klog.SetLogger(logr)
	log.SetLogger(logr)

	// Setup the context,
	ctx, cancel := context.WithCancel(context.Background())

	stop := make(chan os.Signal, 1)

	signal.Notify(stop, syscall.SIGTERM)

	go func() {
		<-stop

		// Cancel anything hanging off the root context.
		cancel()
	}()

	if err := rotator.Run(ctx); err != nil {
		log.Log.Error(err, "runloop initialization failed")
	}
}
