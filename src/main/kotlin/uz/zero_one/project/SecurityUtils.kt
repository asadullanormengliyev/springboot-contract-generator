package uz.zero_one.project

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component

@Component
class SecurityUtils {

    fun getCurrentUserId(): Long{
        val auth = SecurityContextHolder.getContext().authentication
        return auth.details as Long
    }

    fun checkPermissionContractIfOperator(permissionService: PermissionService, contractId: Long, permission: PermissionType) {
        val auth = SecurityContextHolder.getContext().authentication
        val operatorId = auth.details as Long
        val roles = auth.authorities.map { it.authority }
        if ("ROLE_OPERATOR" in roles) {
            permissionService.checkContractPermission(operatorId, contractId, permission)
        }
    }

    fun checkPermissionTemplateIfOperator(permissionService: PermissionService, templateId: Long, permission: PermissionType){
        val auth = SecurityContextHolder.getContext().authentication
        val operatorId = auth.details as Long
        val roles = auth.authorities.map { it.authority }
        if ("ROLE_OPERATOR" in roles) {
            permissionService.checkTemplatePermission(operatorId, templateId, permission)
        }
    }

}