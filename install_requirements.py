import pip._internal
import os
import argparse

PYTHON_REQUIREMENTS_PATH = './requirements/requirements.txt'
BINARY_REQUIREMENTS_PATH = './requirements/binary_requirements.txt'
LINUX_INSTALL_BINARY_COMMAND = 'sudo apt-get install {binary_name}'
OSX_INSTALL_BINARY_COMMAND = 'brew install {binary_name}'
INSTALL_BINARY_COMMANDS = {
    'linux': LINUX_INSTALL_BINARY_COMMAND,
    'osx': OSX_INSTALL_BINARY_COMMAND
}


def install_python_requirements():
    pip_args = ['install', '-r', PYTHON_REQUIREMENTS_PATH]
    pip._internal.main(pip_args)


def install_binary_requirements(os_type='linux'):
    try:
        install_binary_command = INSTALL_BINARY_COMMANDS[os_type]
    except KeyError:
        raise ValueError('{} is not a valid os. Choose linux or osx.')

    with open(BINARY_REQUIREMENTS_PATH) as bin_requirements_file:
        for binary_name in bin_requirements_file.readlines():
            os.system(install_binary_command.format(
                binary_name=binary_name
            ))


def parse_args(args=None):
    parser = argparse.ArgumentParser(description='Install all requirements for mitmhub')
    parser.add_argument('--os', default='linux', help='Which OS are you using? (linux or osx)')
    return parser.parse_args(args)


def main():
    args = parse_args()
    install_python_requirements()
    install_binary_requirements(args.os)


if __name__ == '__main__':
    main()
