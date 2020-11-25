import logging


def file_logger(path: str = 'log.txt', logger_name='default-logger') -> logging.Logger:
    """
    Creates a new logger which logs all incoming logs to stdout and a given file. Also adds the timestamp
    to the log output.
    :param path:
    :param logger_name:
    :return:
    """
    logger = logging.getLogger(logger_name)
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=logging.DEBUG,
        datefmt='%Y-%m-%d %H:%M:%S',
        filename=path,
        filemode='a')
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger
