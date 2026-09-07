const AZURE_STORAGE_CONNECTION =
  "DefaultEndpointsProtocol=https;AccountName=myassets;AccountKey=9mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pXkQ7vRt4Bn9mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pXkQ7vRt4Bn;EndpointSuffix=core.windows.net";

const SERVICE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5bU54UDR3WjhzVDF5QjZjSDBqIiwiaWF0IjoxNzAwMDAwMDAwfQ.9mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pXkQ7vRt4Bn";

const headers = {
  Authorization: "Basic YWRtaW46c3VwM3JTM2NyZXRQdw==",
  "Content-Type": "application/json",
};

module.exports = { AZURE_STORAGE_CONNECTION, SERVICE_JWT, headers };
