package agents

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"unicode/utf8"
)

const (
	// MaxDocuments bounds the Documents of one draft.
	MaxDocuments = 10
	// MaxDocumentBytes bounds one Document, and MaxDocumentsBytes all of them,
	// which grow by a third in base64 and must fit the API's 32 MB request.
	MaxDocumentBytes  = 10 << 20
	MaxDocumentsBytes = 20 << 20
	// MaxDocumentText bounds the text of all Documents, in characters, about
	// 100,000 tokens.
	MaxDocumentText = 400_000

	pdfType  = "application/pdf"
	docxType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	// maxDocxXML bounds what a .docx inflates to, against a zip bomb.
	maxDocxXML = 64 << 20
)

// ErrInvalidDocument is a Document that is empty, too large, unreadable, or of
// a type the Drafter does not read, or too many or too large Documents
// together.
var ErrInvalidDocument = errors.New("invalid document")

// Document is what a Customer Admin gives the Drafter: text, such as plain
// text, Markdown, CSV or JSON, a PDF, or a Word document (.docx).
type Document struct {
	Name      string
	MediaType string
	Data      []byte
}

// source is a Document as the Drafter's prompt names it. A PDF has no Text:
// the model reads it itself, attached in the order of its PDF number.
type source struct {
	Name string `json:"name"`
	PDF  int    `json:"attached_pdf,omitempty"`
	Text string `json:"text,omitempty"`
}

// read is what the Drafter reads of docs: the text of each, and the PDFs it
// is given as they are. It fails with ErrInvalidDocument.
func read(docs []Document) ([]source, [][]byte, error) {
	if len(docs) == 0 || len(docs) > MaxDocuments {
		return nil, nil, fmt.Errorf("%w: give from 1 to %d documents, not %d", ErrInvalidDocument, MaxDocuments, len(docs))
	}
	var (
		sources []source
		pdfs    [][]byte
		size    int
		length  int
	)
	for _, d := range docs {
		size += len(d.Data)
		text, pdf, err := d.read()
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %s: %w", ErrInvalidDocument, d.Name, err)
		}
		if pdf != nil {
			pdfs = append(pdfs, pdf)
			sources = append(sources, source{Name: d.Name, PDF: len(pdfs)})
			continue
		}
		length += utf8.RuneCountInString(text)
		sources = append(sources, source{Name: d.Name, Text: text})
	}
	switch {
	case size > MaxDocumentsBytes:
		return nil, nil, fmt.Errorf("%w: together they take %d bytes, more than %d MB", ErrInvalidDocument, size, MaxDocumentsBytes>>20)
	case length > MaxDocumentText:
		return nil, nil, fmt.Errorf("%w: together they hold %d characters, more than %d", ErrInvalidDocument, length, MaxDocumentText)
	}
	return sources, pdfs, nil
}

// read is the Document's text, or its bytes when it is a PDF.
func (d Document) read() (string, []byte, error) {
	if len(d.Data) == 0 || len(d.Data) > MaxDocumentBytes {
		return "", nil, fmt.Errorf("give from 1 byte to %d MB, not %d bytes", MaxDocumentBytes>>20, len(d.Data))
	}
	mediaType, _, err := mime.ParseMediaType(d.MediaType)
	if err != nil {
		return "", nil, fmt.Errorf("media type %q: %w", d.MediaType, err)
	}
	var text string
	switch {
	case mediaType == pdfType:
		return "", d.Data, nil
	case mediaType == docxType:
		text, err = docxText(d.Data)
	case strings.HasPrefix(mediaType, "text/") || mediaType == "application/json":
		text, err = utf8Text(d.Data)
	default:
		return "", nil, fmt.Errorf("%s is not text, a PDF or a Word document", mediaType)
	}
	if err != nil {
		return "", nil, err
	}
	if text = strings.TrimSpace(text); text == "" {
		return "", nil, errors.New("it holds no text")
	}
	return text, nil, nil
}

func utf8Text(data []byte) (string, error) {
	if !utf8.Valid(data) {
		return "", errors.New("text is not UTF-8")
	}
	return string(data), nil
}

// docxText is the text of word/document.xml, where Word keeps the body: each
// w:t run's text, a w:tab as a tab, a w:br or w:cr as a line break, and a line
// break after each w:p paragraph.
func docxText(data []byte) (string, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("not a Word document: %w", err)
	}
	body, err := archive.Open("word/document.xml")
	if err != nil {
		return "", fmt.Errorf("not a Word document: %w", err)
	}
	defer func() { _ = body.Close() }()
	limited := &io.LimitedReader{R: body, N: maxDocxXML}
	text, err := wordText(xml.NewDecoder(limited))
	if limited.N <= 0 {
		return "", errors.New("the Word document is too large once uncompressed")
	}
	return text, err
}

func wordText(decoder *xml.Decoder) (string, error) {
	var (
		b      strings.Builder
		inText bool
	)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return b.String(), nil
		}
		if err != nil {
			return "", fmt.Errorf("read the Word document: %w", err)
		}
		switch t := token.(type) {
		case xml.StartElement:
			inText = t.Name.Local == "t"
			b.WriteString(map[string]string{"tab": "\t", "br": "\n", "cr": "\n"}[t.Name.Local])
		case xml.EndElement:
			inText = false
			if t.Name.Local == "p" {
				b.WriteByte('\n')
			}
		case xml.CharData:
			if inText {
				b.Write(t)
			}
		}
	}
}
