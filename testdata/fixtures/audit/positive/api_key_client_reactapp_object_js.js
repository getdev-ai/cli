// seeded defect: REACT_APP_ prefixed key inside a config object still gets
// inlined into the client bundle (value is fake)
const config = {
  REACT_APP_GITHUB_TOKEN: "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
};

export default config;
