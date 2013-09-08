#!/usr/bin/env python
#
# Command line utility to run SQL queries against a mongodb database
# or to show what the SQL query will map to in mongo shell.
# http://docs.mongodb.org/manual/reference/sql-comparison/
# http://www.querymongo.com/
#

from optparse import OptionParser
from sys import stdout, exit as sys_exit

# Will go quiet when set to False.
DEBUG = True  # TODO: Make False the default.


def debug_print(func):
    """
    Just a utility decorator to stay out of the way and help with debugging.
    :param func: Name of function.
    :return: function
    """
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        if DEBUG:
            stdout.write('\n++Call {} with A:{} K:{}\n++got back {}\n'.format(
                func.__name__, args, kwargs, ret))
            stdout.flush()
        return ret
    return wrapper

def sql_to_spec(query):
    """
    Convert an SQL query to a mongo spec.
    This only supports select statements. For now.
    :param query: String. A SQL query.
    :return: None or a dictionary containing a mongo spec.
    """
    @debug_print
    def fix_token_list(in_list):
        """
        tokens as List is some times deaply nested and hard to deal with.
        Improve parser grouping remove this.
        """
        if isinstance(in_list, list) and len(in_list) == 1 and \
           isinstance(in_list[0], list):
            return fix_token_list(in_list[0])
        else:
            return [item for item in in_list]

    @debug_print
    def select_func(tokens=None):
        """
        Take tokens and return a dictionary.
        """
        if tokens is None:
            return
        ret = {'find': True,
               'fields': {item: 1 for item in fix_token_list(tokens.asList())}}
        if ret['fields'].get('id'):  # Use _id and not id
            # Drop _id from fields since mongo always return _id
            del(ret['fields']['id'])
        else:
            ret['fields']['_id'] = 0
        if "*" in ret['fields'].keys():
            ret['fields'] = {}
        return ret

    @debug_print
    def where_func(tokens=None):
        """
        Take tokens and return a dictionary.
        """
        if tokens is None:
            return

        tokens = fix_token_list(tokens.asList()) + [None, None, None]
        cond = {'!=': '$ne',
                '>': '$gt',
                '>=': '$gte',
                '<': '$lt',
                '<=': '$lte'}.get(tokens[1])
        if cond is None:
            expr = {tokens[0]: tokens[2].strip('"').strip("'")}
        else:
            expr = {tokens[0]: {cond: tokens[2].strip('"').strip("'")}}

        return expr

    @debug_print
    def combine(tokens=None):
        if tokens:
            tokens = fix_token_list(tokens.asList())
            if len(tokens) == 1:
                return tokens
            else:
                return {'${}'.format(tokens[1]): [tokens[0], tokens[2]]}


    # TODO: Reduce list of imported functions.
    from pyparsing import (Word, alphas, CaselessKeyword, Group, Optional, ZeroOrMore,
                           Forward, Suppress, alphanums, OneOrMore, quotedString,
                           Combine, Keyword, Literal, replaceWith, oneOf,
                           removeQuotes, QuotedString, Dict)

    LPAREN, RPAREN = map(Suppress, "()")
    EXPLAIN = CaselessKeyword('EXPLAIN'
                              ).setParseAction(lambda t: {'explain': True})
    SELECT = Suppress(CaselessKeyword('SELECT'))
    WHERE = Suppress(CaselessKeyword('WHERE'))
    FROM = Suppress(CaselessKeyword('FROM'))
    CONDITIONS = oneOf("= != < > <= >=")
    #CONDITIONS = (Keyword("=") | Keyword("!=") |
    #              Keyword("<") | Keyword(">") |
    #              Keyword("<=") | Keyword(">="))
    AND = CaselessKeyword('and')
    OR = CaselessKeyword('or')

    word_match = Word(alphanums + "._") | quotedString
    statement = Group(word_match + CONDITIONS + word_match
                      ).setParseAction(where_func)
    select_fields = Group(SELECT + (word_match | Keyword("*")) +
                          ZeroOrMore(Suppress(",") +
                                    (word_match | Keyword("*")))
                          ).setParseAction(select_func)

    from_table = (FROM + word_match).setParseAction(
        lambda t: {'collection': t.asList()[0]})
    #word = ~(AND | OR) + word_match

    operation_term = select_fields  # place holder for other SQL statements. ALTER, UPDATE, INSERT
    expr = Forward()
    atom = statement | (LPAREN + expr + RPAREN)
    and_term = (OneOrMore(atom) + ZeroOrMore(AND + atom)
                ).setParseAction(combine)
    or_term = (and_term + ZeroOrMore(OR + and_term)).setParseAction(combine)

    where_clause = (WHERE + or_term
                    ).setParseAction(lambda t: {'spec': t[0]})
    list_term = Optional(EXPLAIN) + operation_term + from_table + \
                Optional(where_clause)
    expr << list_term

    ret = expr.parseString(query.strip())
    query_dict = {}
    _ = map(query_dict.update, ret)
    return query_dict


def spec_str(spec):
    """
    Change a spec to the json object format used in mongo.
    eg. Print dict in python gives: {'a':'b'}
        mongo shell would do {a:'b'}
        Mongo shell can handle both formats but it looks more like the
        official docs to keep to their standard.
    :param spec: Dictionary. A mongo spec.
    :return: String. The spec as it is represended in the mongodb shell examples.
    """

    if spec is None:
        return "{}"
    if isinstance(spec, list):
        out_str = "[" + ', '.join([spec_str(x) for x in spec]) + "]"
    elif isinstance(spec, dict):
        out_str = "{" + ', '.join(["{}:{}".format(x, spec_str(spec[x])
                                                  ) for x in sorted(spec)]) + "}"
    elif isinstance(spec, str) and not spec.isdigit():
        out_str = "'" + spec + "'"
    else:
        out_str = spec

    return out_str


def create_mongo_shell_query(query_dict):
    """
    Create the queries similar to what you will us in mongo shell
    :param query_dict: Dictionary. Internal data structure.
    :return: String. The query that you can use in mongo shell.
    """
    if not query_dict.get('collection'):
        return
    shell_query = "db." + query_dict.get('collection') + "."

    if query_dict.get('find'):
        shell_query += 'find({}, {})'.format(spec_str(query_dict.get('spec')),
                                             spec_str(query_dict.get('fields')))
    if 'explain' in query_dict:
        shell_query += ".explain()"

    return shell_query


def execute_query(spec, connection_string=None):
    """
    Setup a connection to a mongodb server and execute the given query.
    :param spec: Mongo query spec.
    :returns: Mongo curser.
    """
    if connection_string is None:
        connection_string = "mongo://localhost:27017/test"
    if connection_string:
        print "connection to", connection_string
    print "NOT IMPLEMENTED: Must still write the code to connect to mongodb"
    return []

if __name__ == "__main__":
    usage = "usage: %prog [options] select"
    parser = OptionParser(usage=usage)
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="be quiet and do not print out the spec")
    parser.add_option("-m", "--mongo",
                      dest="mongo_server",
                      default=None,
                      help="NOT IMPLEMENTED: mongodb connection string. Default to localhost:27017 no password")
    parser.add_option("-n", "--no_db",
                      action="store_true", dest="no_db", default=False,
                      help="do not run the query against mongo only print out the spec")
    parser.add_option("-j", "--json",
                      action="store_true", dest="format_json", default=False,
                      help="NOT IMPLEMENTED: return the result as json data, Default is in a table")
    parser.add_option("-s", "--shell",  # Someing fun todo one day.
                      action="store_true", dest="shell", default=False,
                      help="NOT IMPLEMENTED: interactive shell just like MySQL but to mongo")

    (options, args) = parser.parse_args()
    if not args:
        parser.print_help()
        sys_exit(1)

    ## Reconstruct the query string
    query = ' '.join([arg if ' ' not in arg else "'" + arg + "'" for arg in args])
    if query[0] in ['"', "'"] and query[0] == query[-1]:
        query = query.strip(query[0])
    if not options.verbose:
        DEBUG = False  # TODO: Reverse this logic when DEBUG defaults to false.
    query_dict = sql_to_spec(query)
    if options.no_db or options.verbose:
        print "The SQL query: ", query
        print "is this mongo query: ", create_mongo_shell_query(query_dict)

    elif not options.no_db:
        result = execute_query(query_dict, options.mongo_server)
        print result
