package uz.zero_one.project

import jakarta.persistence.*
import org.hibernate.annotations.ColumnDefault
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.jpa.domain.support.AuditingEntityListener
import java.util.*

@MappedSuperclass
@EntityListeners(AuditingEntityListener::class)
class BaseEntity(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) var id: Long? = null,
    @CreatedDate @Temporal(TemporalType.TIMESTAMP) var createdDate: Date? = null,
    @LastModifiedDate @Temporal(TemporalType.TIMESTAMP) var modifiedDate: Date? = null,
    @Column(nullable = false) @ColumnDefault(value = "false") var deleted: Boolean = false
)

@Entity
@Table(name = "users")
class User(
    var fullName: String,
    var lastName: String,
    @Column(unique = true)
    var username: String,
    var password: String,
    @Enumerated(EnumType.STRING)
    var role: UserRole,
    @Enumerated(EnumType.STRING)
    var status: Status,
    @ManyToOne
    var organisation: Organisation? = null,

): BaseEntity()

@Entity
class Organisation(
    var name: String,
    var address: String
): BaseEntity()

@Entity
class Template(
    @Column(unique = true)
    var title: String,
    var filePath: String,
    @ManyToOne
    val organisation: Organisation
): BaseEntity()

@Entity
class Contract(
    @ManyToOne
    val template: Template,
    @ManyToOne
    val organisation: Organisation? = null,
    @ManyToOne
    val operator: User,
    var filePath: String,
    @OneToMany(mappedBy = "contract")
    val values: List<ContractValue>

): BaseEntity()

@Entity
class TemplateKey(
    val keyName: String,
    @ManyToOne
    val template: Template,
    var enabled: Boolean
): BaseEntity()

@Entity
class ContractValue(
    var value: String,
    @ManyToOne
    val templateKey: TemplateKey,
    @ManyToOne
    var contract: Contract
): BaseEntity()

@Entity
class ContractAssignment(
    @ManyToOne val contract: Contract,
    @ManyToOne val operator: User,
    @ManyToOne val assignedBy: User,

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    var permissions: MutableSet<PermissionType>
) : BaseEntity()

@Entity
class DownloadHistory(
    @ManyToMany
    @JoinTable(
        name = "download_history_contracts",
        joinColumns = [JoinColumn(name = "download_history_id")],
        inverseJoinColumns = [JoinColumn(name = "contract_id")]
    )
    val contracts: List<Contract>,
    @ManyToOne val user: User,
    val format: String,
    val filePath: String,
    @Enumerated(EnumType.STRING)
    val downloadStatus: DownloadStatus
): BaseEntity()

@Entity
class TemplateAssignment(
    @ManyToOne val template: Template,
    @ManyToOne val operator: User,
    @ManyToOne val assignedBy: User,
    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    var permissions: MutableSet<PermissionType>
) : BaseEntity()

