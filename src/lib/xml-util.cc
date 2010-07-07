/* Copyright 2008 (C) Nicira, Inc.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "xml-util.hh"

#include <xercesc/dom/DOM.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/validators/common/Grammar.hpp>

using namespace std;
using namespace xercesc;

namespace vigil {
namespace xml {

class VigilDOMErrorHandler 
    : public DOMErrorHandler {
public:
    
    VigilDOMErrorHandler(string& error_) 
        : error(error_) {
    }
    
     bool handleError(const DOMError& e) {
         error = XMLString::transcode(e.getMessage());
         return false;
     }
    
private:
    string& error;
};

const DOMNode* get_child_by_tag(const DOMNode* n, const string& tag) {
    DOMNodeList* l = n->getChildNodes();
    for (XMLSize_t i = 0; i < l->getLength(); ++i) {
        if (l->item(i)->getLocalName() == tag) {
            return l->item(i);
        }
    }    

    return 0;
}

const list<DOMNode*> get_children_by_tag(const DOMNode* n, const string& tag) {
    list<DOMNode*> children;
    DOMNodeList* l = n->getChildNodes();
    for (XMLSize_t i = 0; i < l->getLength(); ++i) {
        if (l->item(i)->getLocalName() == tag) {
            children.push_back(l->item(i));
        }
    }    

    return children;
}

/* Initialize the Xerces XML parser */
static DOMBuilder*
init_parser() {
    XMLPlatformUtils::Initialize();
    
    static const XMLCh gLS[] = { chLatin_L, chLatin_S, chNull };
    
    DOMImplementation *impl = 
        DOMImplementationRegistry::getDOMImplementation(gLS);
    DOMBuilder* parser = ((DOMImplementationLS*)impl)->
        createDOMBuilder(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
    try {
        parser->setFeature(XMLUni::fgDOMNamespaces, true);
        parser->setFeature(XMLUni::fgDOMValidation, true);
        parser->setFeature(XMLUni::fgDOMWhitespaceInElementContent, false);
        parser->setFeature(XMLUni::fgXercesSchema, true);
        parser->setFeature(XMLUni::fgXercesSchemaFullChecking, false);
        parser->setFeature(XMLUni::fgXercesUseCachedGrammarInParse, true);        
        parser->setFeature(XMLUni::fgXercesUserAdoptsDOMDocument, true);
        return parser;
    }
    catch (...) {
        return 0;
    }
}

DOMDocument*  load_document(const string& schema, const string& file,
                            string& error_message) {
    error_message = "";
    VigilDOMErrorHandler err_handler(error_message);
    DOMDocument* doc = 0;
    DOMBuilder* parser = init_parser();
    if (!parser) {
        error_message = "XML parser initialization failure.";
        return 0;
    }

    try {
        const static string schema_path = "foo";
        const XMLByte* s = reinterpret_cast<const XMLByte*>(schema.c_str());
        MemBufInputSource mbis(s, schema.size(), 
                               const_cast<char*>(schema_path.c_str()));
        Wrapper4InputSource w4is(&mbis, false);
        parser->loadGrammar(w4is, Grammar::SchemaGrammarType, true);        

        parser->setErrorHandler(&err_handler);
        doc = parser->parseURI(file.c_str());
        
        if (error_message != "") { 
            delete doc;
            doc = 0;
        }
    }
    catch (const XMLException& xe) {
        char* msg = XMLString::transcode(xe.getMessage());
        error_message = msg;
        XMLString::release(&msg);
    }
    catch (const DOMException& de) {
        char* msg = XMLString::transcode(de.getMessage());
        error_message = msg;
        XMLString::release(&msg);
    }

    delete parser;

    return doc;
}

}
}
