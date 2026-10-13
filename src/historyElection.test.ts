import { describe, expect, it } from "vitest";
import { electHistorySharer } from "./historyElection.js";

describe("electHistorySharer", () => {
  it("picks the longest-tenured online member", () => {
    const members = [
      { userId: "300", joinedAt: 3000 },
      { userId: "100", joinedAt: 1000 },
      { userId: "200", joinedAt: 2000 },
    ];
    const online = new Set(["100", "200", "300"]);
    expect(electHistorySharer(members, online, "999")).toBe("100");
  });

  it("never elects the requester, even when oldest", () => {
    const members = [
      { userId: "self", joinedAt: 500 },
      { userId: "other", joinedAt: 1000 },
    ];
    expect(electHistorySharer(members, new Set(["self", "other"]), "self")).toBe("other");
  });

  it("skips offline members", () => {
    const members = [
      { userId: "old-offline", joinedAt: 100 },
      { userId: "new-online", joinedAt: 9000 },
    ];
    expect(electHistorySharer(members, new Set(["new-online"]), "req")).toBe("new-online");
  });

  it("breaks tenure ties by user id for determinism", () => {
    const members = [
      { userId: "b", joinedAt: 1000 },
      { userId: "a", joinedAt: 1000 },
    ];
    expect(electHistorySharer(members, new Set(["a", "b"]), "req")).toBe("a");
  });

  it("returns null when nobody eligible is online", () => {
    const members = [{ userId: "x", joinedAt: 1000 }];
    expect(electHistorySharer(members, new Set(), "req")).toBeNull();
    expect(electHistorySharer(members, new Set(["x"]), "x")).toBeNull();
    expect(electHistorySharer([], new Set(["x"]), "req")).toBeNull();
  });
});
