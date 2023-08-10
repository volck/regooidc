package main

import (
	"context"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown/cache"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"time"
)

type validator struct {
	ctx    context.Context
	pq     rego.PreparedEvalQuery
	cache  cache.InterQueryCache
	logger *logrus.Logger
}

func (v validator) validToken(sEnc map[string]interface{}) (bool bool, msg string) {
	rs, err := v.pq.Eval(v.ctx, rego.EvalInput(sEnc))
	if err != nil {
		panic(err)
	}

	deny := rs[0].Bindings["x"].(map[string]interface{})["deny"]
	allow, _ := rs[0].Bindings["x"].(map[string]interface{})["allow"].(map[string]interface{})
	if len(allow) > 0 {
		for k, _ := range allow {
			return true, k
		}
	} else if len(deny.(map[string]interface{})) > 0 {
		for k, _ := range deny.(map[string]interface{}) {
			return false, k
		}
	}
	return false, ""
}

func noauth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "no auth required")

}

func ping(w http.ResponseWriter, r *http.Request) {

	fmt.Fprint(w, "pong")

}

func (v validator) auth(w http.ResponseWriter, r *http.Request) {

	passAlong := make(map[string]interface{})

	passAlong["Body"] = r.Body
	passAlong["Method"] = r.Method
	passAlong["Header"] = r.Header
	passAlong["URL"] = r.URL

	valid, msg := v.validToken(passAlong)
	if valid {
		v.logger.Info("processed valid request. returning HTTP 200")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	} else {
		w.Header().Set("Content-Type", "application/json")
		v.logger.Info("invalid request. returning HTTP 401")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, msg)
	}

}

func (v validator) RequestLogger(targetMux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		targetMux.ServeHTTP(w, r)

		v.logger.WithFields(logrus.Fields{
			"Time":    time.Now().String(),
			"URI":     r.RequestURI,
			"Ip":      r.RemoteAddr,
			"Elapsed": time.Since(start),
		}).Info(r.Method) // or use Fatal() to force the process to exit with a nonzero code
	})
}

func setLogSettings() *logrus.Logger {
	var logit = logrus.New()
	logit.Formatter = new(logrus.JSONFormatter)
	return logit
}

func main() {
	logger := setLogSettings()

	jwksUrl := os.Getenv("JWKSURL")
	oidcDiscoveryUrl := os.Getenv("OIDC_DISCOVERY")
	if jwksUrl == "" || oidcDiscoveryUrl == "" {
		logger.WithFields(logrus.Fields{
			"JWKSURL":        jwksUrl,
			"OIDC_DISCOVERY": oidcDiscoveryUrl,
		}).Fatalf("Configuration could not be loaded. Missing parameter.")
	}
	runtimeConfig := map[string]any{"JWKSURL": jwksUrl, "OIDC_DISCOVERY": oidcDiscoveryUrl}

	ctx := context.Background()
	stor := inmem.NewFromObject(runtimeConfig)
	txn := storage.NewTransactionOrDie(ctx, stor, storage.WriteParams)

	newCache := cache.NewInterQueryCache(nil)
	var theRego = rego.New(
		rego.Query("x = data.requesthandler"),
		rego.Load([]string{"requesthandler.rego"}, nil),
		rego.InterQueryBuiltinCache(newCache),
		rego.EnablePrintStatements(true),
		rego.Store(stor),
		rego.Transaction(txn))

	pq, err := theRego.PrepareForEval(ctx)
	if err != nil {
		fmt.Println(err)
	}

	err = stor.Commit(ctx, txn)
	if err != nil {
		panic(err)
	}

	v := validator{ctx: ctx, pq: pq, cache: newCache, logger: logger}

	v.logger.WithFields(logrus.Fields{
		"JWKSURL":        jwksUrl,
		"OIDC_DISCOVERY": oidcDiscoveryUrl,
	}).Info("Configuration loaded")

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", v.auth)
	mux.HandleFunc("/noauth", noauth)
	mux.HandleFunc("/ping", ping)
	v.logger.Infof("Starting webserver at port 4000")
	err = http.ListenAndServe(":4000", v.RequestLogger(mux))
	if err != nil {
		logrus.Fatalf("%v", err)
	}

}
