export type TopicNode = {
  id: string;
  name: string;
  description: string;
  count: number;
};

export function searchTopic(pattern: string, nodes: TopicNode[]): TopicNode[] {
  const query = pattern.trim().toLowerCase();
  if (!query) return nodes;

  const terms = query.split(/\s+/).filter((term) => term.length > 0);
  if (terms.length === 0) return nodes;

  return nodes.filter((node) => {
    const haystack = `${node.name} ${node.description}`.toLowerCase();
    return terms.every((term) => haystack.includes(term));
  });
}
