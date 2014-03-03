#include <stdio.h>
#include <stdlib.h>

struct node {
	int id;
	struct node *next;
};
struct node *list;
void print_list()
{
	struct node *p;
	p = list;
	if(!p) printf("NULL");
	while(p){
		printf("%d ", p->id);
		p = p->next;
	}
	printf("\n");
}
#define COUNT 3
int main(void)
{
	int i, id = 0;
	int set[] = {0, 0, 0};
	struct node *p1, *p2, *head;

	for(i=0; i<COUNT; i++){
		p1 = malloc(sizeof(*p1));
		p1->id = set[i];
		p1->next = NULL;
		if(0==i){
			list = head = p1;
		}else{
			head->next = p1;
			head = p1;
		}
	}

	print_list();

	p1 = p2 = head = list;

	while(p1) {
		//scan list
		if(p1->id != id ){
			p2 = p1;
			p1 = p1->next;
			continue;
		}

		//get one
		if(p1 == head){
			head = p2 = p1->next;
			p2 = head;
		}else{
			p2->next = p1->next;
			p2 = p2->next;

		}
		free(p1);
		p1 = p2;
	}

	list = head;
	print_list();

}

