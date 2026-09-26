export class PendingOperationIds {
  constructor({ createId = () => crypto.randomUUID(), limit = 32 } = {}) {
    this.createId = createId;
    this.limit = limit;
    this.ids = new Map();
  }

  key(action, scope, purpose, input) {
    return JSON.stringify([action, scope, purpose, input]);
  }

  get(key) {
    let operationId = this.ids.get(key);
    if (!operationId) {
      operationId = this.createId();
      this.ids.set(key, operationId);
      if (this.ids.size > this.limit) this.ids.delete(this.ids.keys().next().value);
    }
    return operationId;
  }

  complete(key) {
    this.ids.delete(key);
  }

  clear() {
    this.ids.clear();
  }
}
