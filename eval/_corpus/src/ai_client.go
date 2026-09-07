package client

import "net/http"

const (
	openAIKey    = "sk-proj-9mNxP4wZ8sT1yB6cH0jT3BlbkFJL5dF9gA3eU7iO2pXkQ7vR"
	anthropicKey = "sk-ant-api03-9mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pXkQ7vRt4BnYs2Wf8Hj3Kd6Lm9Np1Qr5Tv7Xz0Ab2Cd4Ef6Gh8Jk1AA"
	defaultModel = "claude-sonnet-5"
	timeoutSec   = 30
)

func NewClient() *http.Client {
	return &http.Client{}
}

func Model() string {
	return defaultModel
}
