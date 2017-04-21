#include <stdio.h>
#include <stdlib.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/tree.h>

void print_element_names(xmlNode * a_node){
    xmlNode *cur_node = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            printf("node type: Element, name: %s\n", cur_node->name);
        }

        print_element_names(cur_node->children);
    }
}

int main(int argc, char* argv[]){
	LIBXML_TEST_VERSION

	xmlDoc* doc = xmlReadFile("chooser_in.xml",NULL,0);
	if (doc == NULL) {
		fprintf(stderr, "Failed to parse document\n");
		return 1;
	}
	xmlNode *root_element = xmlDocGetRootElement(doc);
	print_element_names(root_element);


	xmlFreeDoc(doc);


	xmlCleanupParser();
    xmlMemoryDump();
	return 0;
}