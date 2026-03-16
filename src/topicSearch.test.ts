import { describe, expect, it } from "vitest";
import { searchTopic, type TopicNode } from "./topicSearch";

const NODES: TopicNode[] = [
  { id: "cat-adult", name: "Adult Content", description: "Hosts: bad.example", count: 11 },
  { id: "cat-social", name: "Social Media", description: "Hosts: social.example", count: 7 },
  { id: "cat-gaming", name: "Gaming", description: "Hosts: games.example", count: 4 },
];

describe("searchTopic", () => {
  it("returns all nodes on empty pattern", () => {
    expect(searchTopic("", NODES).length).toBe(3);
  });

  it("matches category names", () => {
    const result = searchTopic("social", NODES);
    expect(result.length).toBe(1);
    expect(result[0].id).toBe("cat-social");
  });

  it("matches category descriptions", () => {
    const result = searchTopic("bad.example", NODES);
    expect(result.length).toBe(1);
    expect(result[0].id).toBe("cat-adult");
  });

  it("applies AND behavior across terms", () => {
    const result = searchTopic("adult bad.example", NODES);
    expect(result.length).toBe(1);
    expect(result[0].id).toBe("cat-adult");
  });
});
