basestring = (str, bytes)
string_types = str
integer_types = int
class_types = type
text_type = str
binary_type = bytes

#: Aliases for the utf-8 codec
_UTF8_ALIASES = frozenset(('utf-8', 'UTF-8', 'utf8', 'UTF8', 'utf_8', 'UTF_8',
    'utf', 'UTF', 'u8', 'U8'))
#: Aliases for the latin-1 codec
_LATIN1_ALIASES = frozenset(('latin-1', 'LATIN-1', 'latin1', 'LATIN1',
    'latin', 'LATIN', 'l1', 'L1', 'cp819', 'CP819', '8859', 'iso8859-1',
    'ISO8859-1', 'iso-8859-1', 'ISO-8859-1'))


def to_unicode(obj, encoding='utf-8', errors='replace', nonstring=None):
    '''Convert an object into a :class:`unicode` string
    :arg obj: Object to convert to a :class:`unicode` string.  This should
        normally be a byte :class:`str`
    :kwarg encoding: What encoding to try converting the byte :class:`str` as.
        Defaults to :term:`utf-8`
    :kwarg errors: If errors are found while decoding, perform this action.
        Defaults to ``replace`` which replaces the invalid bytes with
        a character that means the bytes were unable to be decoded.  Other
        values are the same as the error handling schemes in the `codec base
        classes
        <http://docs.python.org/library/codecs.html#codec-base-classes>`_.
        For instance ``strict`` which raises an exception and ``ignore`` which
        simply omits the non-decodable characters.
    :kwarg nonstring: How to treat nonstring values.  Possible values are:
        :simplerepr: Attempt to call the object's "simple representation"
            method and return that value.  Python-2.3+ has two methods that
            try to return a simple representation: :meth:`object.__unicode__`
            and :meth:`object.__str__`.  We first try to get a usable value
            from :meth:`object.__unicode__`.  If that fails we try the same
            with :meth:`object.__str__`.
        :empty: Return an empty :class:`unicode` string
        :strict: Raise a :exc:`TypeError`
        :passthru: Return the object unchanged
        :repr: Attempt to return a :class:`unicode` string of the repr of the
            object
        Default is ``simplerepr``
    :raises TypeError: if :attr:`nonstring` is ``strict`` and
        a non-:class:`basestring` object is passed in or if :attr:`nonstring`
        is set to an unknown value
    :raises UnicodeDecodeError: if :attr:`errors` is ``strict`` and
        :attr:`obj` is not decodable using the given encoding
    :returns: :class:`unicode` string or the original object depending on the
        value of :attr:`nonstring`.
    Usually this should be used on a byte :class:`str` but it can take both
    byte :class:`str` and :class:`unicode` strings intelligently.  Nonstring
    objects are handled in different ways depending on the setting of the
    :attr:`nonstring` parameter.
    The default values of this function are set so as to always return
    a :class:`unicode` string and never raise an error when converting from
    a byte :class:`str` to a :class:`unicode` string.  However, when you do
    not pass validly encoded text (or a nonstring object), you may end up with
    output that you don't expect.  Be sure you understand the requirements of
    your data, not just ignore errors by passing it through this function.
    '''
    # Could use isbasestring/isunicode here but we want this code to be as
    # fast as possible
    if isinstance(obj, basestring):
        if isinstance(obj, text_type):
            return obj
        if encoding in _UTF8_ALIASES:
            return text_type(obj, 'utf-8', errors)
        if encoding in _LATIN1_ALIASES:
            return text_type(obj, 'latin-1', errors)
        return obj.decode(encoding, errors)

    if not nonstring:
        nonstring = 'simplerepr'
    if nonstring == 'empty':
        return u''
    elif nonstring == 'passthru':
        return obj
    elif nonstring == 'simplerepr':
        try:
            simple = obj.__unicode__()
        except (AttributeError, UnicodeError):
            simple = None
        if not simple:
            try:
                simple = text_type(obj)
            except UnicodeError:
                try:
                    simple = obj.__str__()
                except (UnicodeError, AttributeError):
                    simple = u''
        if isinstance(simple, binary_type):
            return text_type(simple, encoding, errors)
        return simple
    elif nonstring in ('repr', 'strict'):
        obj_repr = repr(obj)
        if isinstance(obj_repr, binary_type):
            obj_repr = text_type(obj_repr, encoding, errors)
        if nonstring == 'repr':
            return obj_repr
        raise TypeError('to_unicode was given "%(obj)s" which is neither'
            ' a byte string (str) or a unicode string' %
            {'obj': obj_repr.encode(encoding, 'replace')})

    raise TypeError('nonstring value, %(param)s, is not set to a valid'
        ' action' % {'param': nonstring})
