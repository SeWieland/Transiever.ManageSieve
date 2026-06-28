module.exports = {
  branches: [
    "main",
    { name: "dev", channel: "beta", prerelease: "beta" }
  ],
  tagFormat: "v${version}",
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      { preset: "conventionalcommits" }
    ],
    [
      "@semantic-release/release-notes-generator",
      { preset: "conventionalcommits" }
    ],
    [
      "@droidsolutions-oss/semantic-release-nuget",
      {
        projectPath: "src/Transiever.ManageSieve/Transiever.ManageSieve.csproj",
        usePackageVersion: true,
        nugetRegistries: [
          {
            name: "nuget",
            type: "nuget",
            url: "https://api.nuget.org/v3/index.json",
            tokenEnvVar: "NUGET_API_KEY"
          }
        ]
      }
    ],
    "@semantic-release/github"
  ]
};
