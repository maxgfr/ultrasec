resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "public-read"
}
