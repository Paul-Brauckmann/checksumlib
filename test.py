
def main(path, chunk=1024, *args, **kwargs):
    print(path, chunk)
    print(kwargs.get("cancer"))
    print(args, kwargs)


if __name__ == "__main__":
    main("test")
    main("1234", 2048)
    main("test", 2048, "1234", "rhhgi", cancer=True)

