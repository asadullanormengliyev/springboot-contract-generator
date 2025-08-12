package uz.zero_one.project


import org.springframework.web.multipart.MultipartFile
import java.text.SimpleDateFormat

data class BaseMessage(val code: Int,val message: String?)

data class AdminCreateRequest(
    val fullName: String,
    val lastName: String,
    val username: String,
    val password: String,
    val role: UserRole,
    val status: Status,
)

data class JwtResponseDto(
    val accessToken: String,
    val refreshToken: String?
)

data class OrganisationCreateRequest(
    val name: String,
    val address: String
)

data class OrganisationResponse(
    val id: Long,
    val name: String,
    val address: String
){
    companion object{
        fun toResponse(organisation: Organisation): OrganisationResponse{
            return OrganisationResponse(
                id = organisation.id!!,
                name = organisation.name,
                address = organisation.address,
            )
        }
    }
}

data class OrganisationUpdate(
    val name: String?,
    val address: String?
)

data class GetOneOrganisation(
    val id: Long,
    val name: String,
    val address: String
){
    companion object{
        fun toResponse(organisation: Organisation): GetOneOrganisation{
            return GetOneOrganisation(
                id = organisation.id!!,
                name = organisation.name,
                address = organisation.address,
            )
        }
    }
}

data class UserCreateRequest(
    val fullName: String,
    val lastName: String,
    val username: String,
    val password: String,
    val role: UserRole? = UserRole.OPERATOR,
    val status: Status? = Status.ACTIVE,
    val organisationId: Long
)

data class UserRequest(
    val fullName: String,
    val lastName: String,
    val username: String,
    val password: String,
    val role: UserRole? = UserRole.OPERATOR,
    val status: Status? = Status.ACTIVE,
)

data class GetOneUser(
    val id: Long,
    val fullName: String,
    val lastName: String,
    val username: String,
    val role: UserRole,
    val status: Status,
    val organisationId: Long?
){
    companion object{
        fun toResponse(user: User): GetOneUser{
            return GetOneUser(
                id = user.id!!,
                fullName = user.fullName,
                lastName = user.lastName,
                username = user.username,
                role = user.role,
                status = user.status,
                organisationId = user.organisation?.id
            )
        }
    }
}

data class GetOneTemplate(
    val id: Long,
    val title: String,
    val url: String
){
    companion object{
        fun toResponse(template: Template): GetOneTemplate {
            return GetOneTemplate(
                id = template.id!!,
                title = template.title,
                url = template.filePath
            )
        }
    }
}

data class GetTemplateKeyDto(
    val id: Long,
    val keyName: String,
    val templateId: Long,
    val enabled: Boolean
){
    companion object{
        fun toResponse(templateKey: TemplateKey): GetTemplateKeyDto{
            val cleanedKeyName = templateKey.keyName.removePrefix("{").removeSuffix("}")
            return GetTemplateKeyDto(
                id = templateKey.id!!,
                keyName = cleanedKeyName,
                templateId = templateKey.template.id!!,
                enabled = templateKey.enabled
            )
        }
    }
}

data class CreateContractRequest(
    val templateId: Long,
    val values: List<ContractValueRequest>,
)

data class ContractValueRequest(
    val templateKeyId: Long,
    val value: String? = null,
)

data class GetOneContract(
    val id: Long,
    val templateTitle: String,
    val filePath: String,
){
    companion object{
        fun toResponse(contract: Contract): GetOneContract{
            return GetOneContract(
                id = contract.id!!,
                templateTitle = contract.template.title,
                filePath = contract.filePath
            )
        }
    }
}

data class UserUpdateDto(
    val fullName: String?,
    val lastName: String?,
    val username: String?,
    val password: String?,
)

data class UserDto(
    val id: Long,
    val fullName: String,
    val lastName: String,
    val username: String,
    val status: Status?,
    val role: String,
) {
    companion object {
        fun toResponse(user: User): UserDto {
            return UserDto(
                id = user.id!!,
                fullName = user.fullName,
                lastName = user.lastName,
                username = user.username,
                status = user.status,
                role = user.role.name
            )
        }
    }
}

data class UserStatusUpdateRequest(
    val status: Status
)

data class UserRoleUpdateRequest(
    val role: UserRole
)

data class UpdateTemplateDto(
    val title: String?,
    val file: MultipartFile?
)

data class UpdateTemplateKeyEnabledRequest(
    val templateKeyId: Long,
    val enabled: Boolean
)

data class ContractAssignRequest(
    val operatorId: Long,
    val permissions: Set<PermissionDto>
)

data class GenerateRequest(
    val contractIds: List<Long>,
    val format: String
)

data class DownloadHistoryResponse(
    val id: Long,
    val filePath: String,
    val format: String,
    val createdDate: String?,
    val downloadStatus: DownloadStatus
) {
    companion object {
        fun from(entity: DownloadHistory): DownloadHistoryResponse {
            val formatter = SimpleDateFormat("dd-MM-yyyy HH:mm:ss")
            return DownloadHistoryResponse(
                id = entity.id!!,
                filePath = entity.filePath,
                format = entity.format,
                createdDate = formatter.format(entity.createdDate),
                downloadStatus = entity.downloadStatus
            )
        }
    }
}

data class UpdateContractValueDto(
    val templateKeyId: Long,
    val contractValueId: Long,
    val value: String
)

data class UpdateContractRequest(
     val values:List<UpdateContractValueDto>
)

data class GetContractValueAndTemplateKeyDto(
    val templateKeyId: Long,
    val contractValueId: Long,
    val keyName: String,
    val value: String?,
    val enabled: Boolean
){
    companion object{
        fun toResponse(contractValue: ContractValue):GetContractValueAndTemplateKeyDto{
            val cleanedKeyName = contractValue.templateKey.keyName.removePrefix("{").removeSuffix("}")
            val cleanedValue = if (contractValue.value.startsWith("{") == true && contractValue.value.endsWith("}") == true) {
                null
            } else {
                contractValue.value
            }
            return GetContractValueAndTemplateKeyDto(
                templateKeyId = contractValue.templateKey.id!!,
                contractValueId=contractValue.id!!,
                keyName = cleanedKeyName,
                value = cleanedValue,
                enabled = contractValue.templateKey.enabled
            )
        }
    }
}

data class TemplateAssignRequest(
    val operatorId: Long,
    val permissions: Set<PermissionDto>
)

data class PermissionDto(
    val permission: PermissionType,
    val enabled: Boolean
)

data class PermissionCountResponse(
    val totalPermission: Int,
    val grantedPermissions: Int
)

data class UserWithPermissionDto(
    val id: Long,
    val fullName: String,
    val lastName: String,
    val username: String,
    val status: Status?,
    val role: String,
    val permissions: Set<PermissionType>,
) {
    companion object {
        fun fromAssignment(assignment: ContractAssignment): UserWithPermissionDto {
            val user = assignment.operator
            return UserWithPermissionDto(
                id = user.id!!,
                fullName = user.fullName,
                lastName = user.lastName,
                username = user.username,
                status = user.status,
                role = user.role.name,
                permissions = assignment.permissions,
            )
        }

        fun fromTemplateAssignment(assignment: TemplateAssignment): UserWithPermissionDto{
            val user = assignment.operator
            return UserWithPermissionDto(
                id = user.id!!,
                fullName = user.fullName,
                lastName = user.lastName,
                username = user.username,
                status = user.status,
                role = user.role.name,
                permissions = assignment.permissions,
            )
        }
    }
}

data class OperatorAssignedDto(
    val templateId: Long,
    val permissions: Map<PermissionType, Boolean>
)

data class OperatorAssignedResponse(
    val assigned: List<OperatorAssignedDto>
)

data class OperatorAssignedContractDto(
    val contractId: Long,
    val permissions: Map<PermissionType, Boolean>
)

data class OperatorAssignedContractResponse(
    val assigned: List<OperatorAssignedContractDto>
)

data class ContractsByOrganizationDto(
    val id: Long,
    val title: String,
    val filePath: String,
    val fullName: String,
    val lastName: String
){
    companion object{
        fun toResponse(contract: Contract):ContractsByOrganizationDto{
            return ContractsByOrganizationDto(
                id = contract.id!!,
                title = contract.template.title,
                filePath = contract.filePath,
                fullName = contract.operator.fullName,
                lastName = contract.operator.lastName,
            )
        }
    }
}

data class OperatorWithPermissionDto(
    val id: Long,
    val fullName: String,
    val lastName: String,
    val username: String,
    val role: String,
    val status: Status,
    val organisationId: Long,
    val permissions: Map<PermissionType, Boolean>,
    val permissionCountResponse: PermissionCountResponse
)