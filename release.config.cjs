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
      {
        preset: "conventionalcommits",
        presetConfig: {
          types: [
            { type: "feat", section: "Features" },
            { type: "feature", section: "Features" },
            { type: "fix", section: "Bug Fixes" },
            { type: "perf", section: "Performance Improvements" },
            { type: "revert", section: "Reverts" },
            { type: "chore", scope: "deps", section: "Dependency Updates" },
            { type: "chore", scope: "deps-dev", section: "Dependency Updates" }
          ]
        }
      }
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
        prepareCmd: "dotnet pack src/Transiever.ManageSieve.Cli/Transiever.ManageSieve.Cli.csproj --configuration Release -p:PackageVersion=${nextRelease.version} --output out",
        successCmd: "if [ -n \"$GITHUB_OUTPUT\" ]; then echo \"release_tag=${nextRelease.gitTag}\" >> \"$GITHUB_OUTPUT\"; fi"
      }
    ],
    ["@semantic-release/github", { draftRelease: true }]
  ]
};
