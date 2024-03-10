import sys

_SIZES = ('', 'K', 'M', 'G', 'T')


class Output:
    def begin(self, name: str):
        raise NotImplementedError()

    def end(self):
        raise NotImplementedError()

    def write(self, name: str, value, typ: str, *args):
        raise NotImplementedError()


class TextOutput(Output):
    def __init__(self, output=None):
        if output is None:
            output = sys.stdout

        self._padding = 0
        self._output = output

    def begin(self, name: str):
        self._print(name, ':')
        self._padding += 1

    def end(self):
        self._output.write('\n')
        self._padding -= 1

    def write(self, name: str, value, typ: str, *args):
        self._print(name, ': ', self._format(value, typ, *args))

    def _print(self, *args):
        self._output.write('    ' * self._padding + ''.join(args) + '\n')

    @staticmethod
    def _format(value, typ: str, *args):
        if typ == 'count':
            return str(value)

        if typ == 'raw':
            if value is None:
                return '<none>'
            return value

        if typ == 'address':
            return hex(value)

        if typ == 'datetime':
            return value.strftime('%d.%m.%Y %H:%M:%S')

        if typ == 'enum':
            return value.name

        if typ == 'flags':
            value = str(value)
            if '.' in value:
                return value[value.index('.') + 1:]
            return value

        if typ == 'alignment':
            if bin(value).count('1') != 1:
                return f"<bad alignment {hex(value)}>"

            v = 0
            while value != 1:
                value >>= 1
                v += 1

            return f"2^{v}"

        if typ == 'version':
            return f"{value[0]}.{value[1]}"

        if typ == 'size':
            div = 0

            while value >= 512:
                value /= 1024
                div += 1

            if int(value) == value:
                return f"{int(value)}{_SIZES[div]}B"
            return f"{value:.2f}{_SIZES[div]}B"


class JsonOutput(Output):
    def __init__(self):
        self.result = {}
        self._stack = [self.result]

    def begin(self, name: str):
        new = {}
        self._stack[-1][name] = new
        self._stack.append(new)

    def end(self):
        self._stack.pop(-1)

    def write(self, name: str, value, typ: str, *args):
        self._stack[-1][name] = self._format(value, typ, *args)

    @staticmethod
    def _format(value, typ: str, *args):
        if typ in {'count', 'address', 'size', 'raw'}:
            return value

        if typ == 'datetime':
            return value.strftime('%d.%m.%Y %H:%M:%S')

        if typ == 'enum':
            return value.value

        if typ == 'flags':
            return int(value)

        if typ == 'alignment':
            if bin(value).count('1') != 1:
                return f"<bad alignment {hex(value)}>"

            v = 0
            while value != 1:
                value >>= 1
                v += 1

            return v

        if typ == 'version':
            return [value[0], value[1]]
