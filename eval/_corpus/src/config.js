const path = require("path");

const config = {
  appName: "example-app",
  port: process.env.PORT || 3000,
  githubToken: "ghp_9mNxP4wZ8sT1yB6cH0jL5dF9gA3eU7iO2pXk",
  slackWebhook: "https://hooks.slack.com/services/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",
  databaseUrl: process.env.DATABASE_URL,
  logLevel: "info",
};

const paths = {
  root: path.resolve(__dirname, ".."),
  uploads: "/var/data/uploads",
};

module.exports = { config, paths };
