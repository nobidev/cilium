module.exports = {
  repositories: ["isovalent/cilium"],
  username: "isovalent-renovate[bot]",
  secrets: {
    RH_REGISTRY_USERNAME: "{{ process.env.RH_REGISTRY_USERNAME }}",
    RH_REGISTRY_PASSWORD: "{{ process.env.RH_REGISTRY_PASSWORD }}",
  },
  hostRules: [
    {
      matchHost: "https://registry.redhat.io",
      hostType: "docker",
      username: "{{ process.env.RH_REGISTRY_USERNAME }}",
      password: "{{ process.env.RH_REGISTRY_PASSWORD }}",
    },
  ],
  allowedCommands: [
    '^make .*$',
  ],
};
