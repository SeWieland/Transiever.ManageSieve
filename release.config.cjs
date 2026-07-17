module.exports = {
  branches: [
    "main",
    { name: "dev", channel: "beta", prerelease: "beta" }
  ],
  tagFormat: "v${version}",
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "conventionalcommits",
        releaseRules: [
          { type: "chore", scope: "deps", release: "patch" }
        ]
      }
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
    [
      "@semantic-release/exec",
      {
        prepareCmd: "bash .github/scripts/build-release-assets.sh ${nextRelease.version}"
      }
    ],
    [
      "@semantic-release/github",
      {
        assets: [
          {
            path: "artifacts/msieve-win-x64.zip",
            name: "msieve-${nextRelease.gitTag}-win-x64.zip",
            label: "msieve Windows x64"
          },
          {
            path: "artifacts/msieve-win-x86.zip",
            name: "msieve-${nextRelease.gitTag}-win-x86.zip",
            label: "msieve Windows x86"
          },
          {
            path: "artifacts/msieve-linux-x64.tar.gz",
            name: "msieve-${nextRelease.gitTag}-linux-x64.tar.gz",
            label: "msieve Linux x64"
          }
        ]
      }
    ]
  ]
};
