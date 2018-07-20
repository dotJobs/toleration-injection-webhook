package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"os"

	"github.com/mattbaird/jsonpatch"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	// TODO(https://github.com/kubernetes/kubernetes/issues/57982)
	defaulter = runtime.ObjectDefaulter(runtimeScheme)

	match_label_key = os.Getenv("MATCH_LABEL_KEY")
	match_label_value = os.Getenv("MATCH_LABEL_VALUE")
	toleration_key  = os.Getenv("TOLERATION_KEY")
	toleration_value  = os.Getenv("TOLERATION_VALUE")
	toleration_effect  = corev1.TaintEffect(os.Getenv("TOLERATION_EFFECT"))

	elasticToleration = []corev1.Toleration{
		{Key: toleration_key, Value: toleration_value, Effect: toleration_effect},
	}
)

// the Path of the JSON patch is a JSON pointer value
// so we need to escape any "/"s in the key we add to the annotation
// https://tools.ietf.org/html/rfc6901
func escapeJSONPointer(s string) string {
	esc := strings.Replace(s, "~", "~0", -1)
	esc = strings.Replace(esc, "/", "~1", -1)
	return esc
}

var kubeSystemNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

func handler(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling a request")
	log.Printf("New Toleration Object: %v", elasticToleration)
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("error: %v", err)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.Printf("Wrong content type. Got: %s", contentType)
		return
	}

	admReq := v1beta1.AdmissionReview{}
	admResp := v1beta1.AdmissionReview{}

	if _, _, err := deserializer.Decode(body, nil, &admReq); err != nil {
		log.Printf("Could not decode body: %v", err)
		admResp.Response = admissionError(err)
	} else {
		admResp.Response = getAdmissionDecision(&admReq)
	}

	resp, err := json.Marshal(admResp)
	if err != nil {
		log.Printf("error marshalling decision: %v", err)
	}
	log.Printf(string(resp))
	if _, err := w.Write(resp); err != nil {
		log.Printf("error writing response %v", err)
	}
}

func admissionError(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{Message: err.Error()},
	}
}

func getAdmissionDecision(admReq *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := admReq.Request
	var pod corev1.Pod

	err := json.Unmarshal(req.Object.Raw, &pod)
	if err != nil {
		log.Printf("Could not unmarshal raw object: %v", err)
		return admissionError(err)
	}

	log.Printf("AdmissionReview for Kind=%v Namespace=%v Name=%v UID=%v Operation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, req.UID, req.Operation, req.UserInfo)

	if !shouldInject(&pod.ObjectMeta) {
		log.Printf("Skipping inject for %s %s", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
			UID:     req.UID,
		}
	}

	patch, err := patchConfig(&pod, elasticToleration)

	if err != nil {
		log.Printf("Error creating conduit patch: %v", err)
		return admissionError(err)
	}

	jsonPatchType := v1beta1.PatchTypeJSONPatch

	return &v1beta1.AdmissionResponse{
		Allowed:   true,
		Patch:     patch,
		PatchType: &jsonPatchType,
		UID:       req.UID,
	}
}

func patchConfig(pod *corev1.Pod, tolerations []corev1.Toleration) ([]byte, error) {
	var patch []jsonpatch.JsonPatchOperation

	patch = append(patch, addTolerations(pod.Spec.Tolerations, tolerations)...)
	return json.Marshal(patch)
}

func addTolerations(current []corev1.Toleration, toAdd []corev1.Toleration) []jsonpatch.JsonPatchOperation {
	var patch []jsonpatch.JsonPatchOperation

  for _,toleration := range toAdd {
		log.Printf("toleration object: %v", toleration)
		patch = append(patch, jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      "/spec/tolerations",
			Value:     []corev1.Toleration{toleration},
		})
	}
  log.Printf("patch object: %v", patch)
	return patch
}

func shouldInject(metadata *metav1.ObjectMeta) bool {
	shouldInject := false
	log.Println("Checking to see if labels match for injection")
  for key, value := range metadata.Labels {
		log.Printf("label key: %s label value: %s match key: %s match value %s", key, value, match_label_key, match_label_value)
		if key == match_label_key {
			log.Println("matched key")
			if value == match_label_value {
				shouldInject = true
				log.Println("Injecting toleration")
			}
		}
	}

	return shouldInject
}

func main() {
	addr := flag.String("addr", ":8080", "address to serve on")

	http.HandleFunc("/", handler)

	flag.CommandLine.Parse([]string{}) // hack fix for https://github.com/kubernetes/kubernetes/issues/17162

	log.Printf("Starting HTTPS webhook server on %+v", *addr)
	clientset := getClient()
	server := &http.Server{
		Addr:      *addr,
		TLSConfig: configTLS(clientset),
	}
	go selfRegistration(clientset, caCert)
	server.ListenAndServeTLS("", "")
}
