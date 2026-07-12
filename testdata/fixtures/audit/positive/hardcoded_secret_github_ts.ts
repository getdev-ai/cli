// seeded defect: GitHub personal access token hardcoded (value is fake)
const githubToken: string = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE";

export async function listRepos(): Promise<Response> {
  return fetch("https://api.github.com/user/repos", {
    headers: { Authorization: `token ${githubToken}` },
  });
}
