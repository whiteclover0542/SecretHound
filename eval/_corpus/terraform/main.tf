provider "aws" {
  region     = "ap-northeast-2"
  access_key = "AKIA2E0A8F3B244C9986"
  secret_key = "kR7vQ2mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pX"
}

resource "aws_s3_bucket" "assets" {
  bucket = "my-app-assets"
  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0c9c942bd7bf113a2"
  instance_type = "t3.micro"
}
