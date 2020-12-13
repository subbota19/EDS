from eds_algorithm import EDS


def main():
    eds_obj = EDS(text=str(input("Please input test:")))
    eds_obj.encrypt()
    eds_obj.decrypt()


if __name__ == "__main__":
    main()
