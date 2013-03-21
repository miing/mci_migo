# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from BeautifulSoup import (
    BeautifulSoup, CData, Comment, Declaration, NavigableString, PageElement,
    ProcessingInstruction, SoupStrainer, Tag)
import re

IGNORED_ELEMENTS = [Comment, Declaration, ProcessingInstruction]
ELEMENTS_INTRODUCING_NEWLINE = [
    'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'pre', 'dl',
    'div', 'noscript', 'blockquote', 'form', 'hr', 'table', 'fieldset',
    'address', 'li', 'dt', 'dd', 'th', 'td', 'caption', 'br']


NEWLINES_RE = re.compile(u'\n+')
LEADING_AND_TRAILING_SPACES_RE = re.compile(
    u'(^[ \t]+)|([ \t]$)', re.MULTILINE)
TABS_AND_SPACES_RE = re.compile(u'[ \t]+')
NBSP_RE = re.compile(u'&nbsp;|&#160;')


class DuplicateIdError(Exception):
    """Raised by find_tag_by_id if more than one element has the given id."""


def find_tag_by_id(content, id):
    """Find and return the tag with the given ID"""
    if isinstance(content, PageElement):
        elements_with_id = content.findAll(True, {'id': id})
    else:
        elements_with_id = [tag for tag in BeautifulSoup(
                            content, parseOnlyThese=SoupStrainer(id=id))]
    if len(elements_with_id) == 0:
        return None
    elif len(elements_with_id) == 1:
        return elements_with_id[0]
    else:
        raise DuplicateIdError(
            'Found %d elements with id %r' % (len(elements_with_id), id))


def extract_text(content, extract_image_text=False, skip_tags=None):
    """Return the text stripped of all tags.

    All runs of tabs and spaces are replaced by a single space and runs of
    newlines are replaced by a single newline. Leading and trailing white
    spaces are stripped.
    """
    if skip_tags is None:
        skip_tags = ['script']
    if not isinstance(content, PageElement):
        soup = BeautifulSoup(content)
    else:
        soup = content

    result = []
    nodes = list(soup)
    while nodes:
        node = nodes.pop(0)
        if type(node) in IGNORED_ELEMENTS:
            continue
        elif isinstance(node, CData):
            # CData inherits from NavigableString which inherits from unicode,
            # but contains a __unicode__() method that calls __str__() that
            # wraps the contents in <![CDATA[...]]>.  In Python 2.4, calling
            # unicode(cdata_instance) copies the data directly so the wrapping
            # does not happen.  Python 2.5 changed the unicode() function (C
            # function PyObject_Unicode) to call its operand's __unicode__()
            # method, which ends up calling CData.__str__() and the wrapping
            # happens.  We don't want our test output to have to deal with the
            # <![CDATA[...]]> wrapper.
            #
            # The CData class does not override slicing though, so by slicing
            # node first, we're effectively turning it into a concrete unicode
            # instance, which does not wrap the contents when its __unicode__()
            # is called of course.  We could remove the unicode() call
            # here, but we keep it for consistency and clarity purposes.
            result.append(unicode(node[:]))
        elif isinstance(node, NavigableString):
            result.append(unicode(node))
        else:
            if isinstance(node, Tag):
                # If the node has the class "sortkey" then it is invisible.
                if node.get('class') == 'sortkey':
                    continue
                elif getattr(node, 'name', '') in skip_tags:
                    continue
                if node.name.lower() in ELEMENTS_INTRODUCING_NEWLINE:
                    result.append(u'\n')

                # If extract_image_text is True and the node is an
                # image, try to find its title or alt attributes.
                if extract_image_text and node.name.lower() == 'img':
                    # Title outweighs alt text for the purposes of
                    # pagetest output.
                    if node.get('title') is not None:
                        result.append(node['title'])
                    elif node.get('alt') is not None:
                        result.append(node['alt'])

            # Process this node's children next.
            nodes[0:0] = list(node)

    text = u''.join(result)
    text = NBSP_RE.sub(' ', text)
    text = TABS_AND_SPACES_RE.sub(' ', text)
    text = LEADING_AND_TRAILING_SPACES_RE.sub('', text)
    text = NEWLINES_RE.sub('\n', text)

    return text.strip()


def find_tags_by_class(content, class_, only_first=False):
    """Find and return one or more tags matching the given class(es)"""
    match_classes = set(class_.split())

    def class_matcher(value):
        if value is None:
            return False
        classes = set(value.split())
        return match_classes.issubset(classes)
    soup = BeautifulSoup(
        content, parseOnlyThese=SoupStrainer(attrs={'class': class_matcher}))
    if only_first:
        find = BeautifulSoup.find
    else:
        find = BeautifulSoup.findAll
    return find(soup, attrs={'class': class_matcher})

def find_tags_by_tag_name(content, name):
    soup = BeautifulSoup(content, parseOnlyThese=SoupStrainer(name))
    return soup.findAll(name)

def find_main_content(content):
    """Return the main content of the page, excluding any portlets."""
    main_content = find_tag_by_id(content, 'maincontent')
    if main_content is None:
        # One-column pages don't use a <div id="maincontent">, so we
        # use the next best thing: <div id="container">.
        main_content = find_tag_by_id(content, 'container')
    if main_content is None:
        # Simple pages have neither of these, so as a last resort, we get
        # the page <body>.
        main_content = BeautifulSoup(content).body
    return main_content


def hrefs(tags):
    """Extracts just the hrefs of the given tags"""
    return '\n'.join([t['href'] for t in tags])


def get_feedback_messages(content):
    """Find and return the feedback messages of the page."""
    message_classes = ['message', 'message error', 'message informational',
                       'message warning']
    soup = BeautifulSoup(
        content,
        parseOnlyThese=SoupStrainer(['div'], {'class': message_classes}))
    return [extract_text(tag) for tag in soup]
