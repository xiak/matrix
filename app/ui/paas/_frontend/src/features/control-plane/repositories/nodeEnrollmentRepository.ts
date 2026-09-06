import type {
  CreateNodeEnrollmentRequest,
  NodeEnrollment,
  NodeEnrollmentCreation,
  NodeEnrollmentInventory,
  NodeEnrollmentVersionCommand
} from "../domain/nodeEnrollments";

export interface NodeEnrollmentRepository {
  load(credential: string, signal?: AbortSignal): Promise<NodeEnrollmentInventory>;
  create(
    credential: string,
    publicOrigin: string,
    request: CreateNodeEnrollmentRequest
  ): Promise<NodeEnrollmentCreation>;
  revoke(credential: string, command: NodeEnrollmentVersionCommand): Promise<NodeEnrollment>;
  regenerate(
    credential: string,
    publicOrigin: string,
    command: NodeEnrollmentVersionCommand,
    wrappingPublicKey: string
  ): Promise<NodeEnrollmentCreation>;
}
