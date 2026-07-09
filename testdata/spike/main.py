def load_config(path):
    with open(path) as f:
        return f.read()


def main():
    print(load_config("config.toml"))


class Runner:
    def run(self):
        main()
