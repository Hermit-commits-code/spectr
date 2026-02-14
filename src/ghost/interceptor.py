import textwrap

def generate_alias():
    """
    Outputs clean shell configuration to intercept package installs.
    """
    hook = """
        pip() {
            if [[ "$1" == "install" && -n "$2" && "$2" != -* ]]; then
                ghost "$2"
                if [ $? -eq 0 ]; then
                    command pip "$@"
                else
                    echo "🛡️  Ghost blocked the installation of '$2'."
                    return 1
                fi
            else
                command pip "$@"
            fi
        }

        uv() {
            if [[ "$1" == "pip" && "$2" == "install" && -n "$3" ]]; then
                ghost "$3"
                if [ $? -eq 0 ]; then
                    command uv "$@"
                else
                    echo "🛡️  Ghost blocked the installation of '$3'."
                    return 1
                fi
            else
                command uv "$@"
            fi
        }
    """
    # .strip() removes leading/trailing newlines that cause 'unexpected token' errors
    print(textwrap.dedent(hook).strip())
